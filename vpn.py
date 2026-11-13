import base64
import configparser
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request

class ActionError(Exception):
    pass

def diagnostic(message):
    print(message, file=sys.stderr, flush=True)

def failure_detail(error):
    if isinstance(error, ActionError):
        return str(error)
    details = []
    current = error
    seen = set()
    while isinstance(current, BaseException) and id(current) not in seen and len(details) < 4:
        seen.add(id(current))
        detail = type(current).__name__
        for field in ('errno', 'code', 'verify_code'):
            value = getattr(current, field, None)
            if type(value) is int:
                detail += ' ' + field + '=' + str(value)
        details.append(detail)
        current = current.__cause__ or getattr(current, 'reason', None) or current.__context__
    trace = error.__traceback__
    location = ''
    while trace:
        if trace.tb_frame.f_code.co_filename == __file__:
            location = ' at vpn.py:' + str(trace.tb_lineno)
        trace = trace.tb_next
    return 'WireGuard operation failed: ' + ' -> '.join(details) + location

def redact(text, secrets=()):
    for value in sorted(set(secrets), key=len, reverse=True):
        if value:
            text = text.replace(value, '[REDACTED]')
    text = re.sub(r'((?:PrivateKey|PresharedKey)\s*=\s*)\S+',
                  r'\1[REDACTED]', text, flags=re.IGNORECASE)

    return '\n'.join('    ' + line for line in text[-20000:].splitlines())

def run(*args, timeout=30, secrets=(), log=None):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ActionError('Command timed out after ' + str(timeout) + ' seconds: ' + Path(args[0]).name) from None
    except OSError as error:
        raise ActionError('Command unavailable: ' + Path(args[0]).name + ' (' + type(error).__name__ + ')') from None
    safe = redact(result.stdout + result.stderr, secrets)
    if log:
        with Path(log).open('a') as output:
            output.write(safe + '\n')
    if result.returncode:
        diagnostic(safe)
        raise ActionError('Command failed: ' + Path(args[0]).name + ' (exit ' + str(result.returncode) + ')')
    return result.stdout.strip()

def route(address):
    text = run('route', '-n', 'get', '-inet', address)
    return {key.strip(): value.strip() for line in text.splitlines() if ':' in line
            for key, value in [line.split(':', 1)]}

def github_ranges(metadata):
    networks = set()
    try:
        for service in ('web', 'api', 'git'):
            entries = metadata.get(service)
            if not isinstance(entries, list) or not entries:
                raise ValueError()
            for entry in entries:
                network = ipaddress.ip_network(entry)
                if network.version == 4:
                    if not network.is_global or network.prefixlen < 8:
                        raise ValueError()
                    networks.add(network)
        if not networks or len(networks) > 512:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ActionError('Invalid GitHub IPv4 range metadata.') from None
    return [str(network) for network in ipaddress.collapse_addresses(networks)]

def parse_config(raw, cidrs):
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    secrets = []
    try:
        config.read_string(raw)
        if config.defaults() or config.sections() != ['Interface', 'Peer']:
            raise ValueError()
        interface = config['Interface']
        peer = config['Peer']
        if set(interface) - {'PrivateKey', 'Address', 'ListenPort', 'MTU', 'DNS', 'SaveConfig'}:
            raise ValueError()
        if set(peer) - {'PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive'}:
            raise ValueError()
        for section, key in [(interface, 'PrivateKey'), (peer, 'PublicKey')]:
            if len(base64.b64decode(section[key], validate=True)) != 32:
                raise ValueError()
        secrets.append(interface['PrivateKey'])
        if 'PresharedKey' in peer:
            if len(base64.b64decode(peer['PresharedKey'], validate=True)) != 32:
                raise ValueError()
            secrets.append(peer['PresharedKey'])
        address = ipaddress.ip_interface(interface['Address'])
        if (address.version != 4 or address.network.prefixlen != 32 or
                address.ip.is_loopback or address.ip.is_multicast or address.ip.is_unspecified):
            raise ValueError()
        endpoint, port = peer['Endpoint'].rsplit(':', 1)
        endpoint_ip = ipaddress.IPv4Address(endpoint)
        if (endpoint_ip.is_loopback or endpoint_ip.is_multicast or endpoint_ip.is_unspecified
                or endpoint_ip.is_link_local or not 1 <= int(port) <= 65535):
            raise ValueError()
        if any(endpoint_ip in ipaddress.IPv4Network(cidr) for cidr in cidrs):
            raise ValueError()
        for section, key, low, high in [(interface, 'ListenPort', 1, 65535),
                                       (interface, 'MTU', 576, 9000),
                                       (peer, 'PersistentKeepalive', 0, 65535)]:
            if key in section and not low <= int(section[key]) <= high:
                raise ValueError()
    except Exception:

        raise ActionError('Invalid config: require one IPv4 /32 client, one peer, a numeric '
                          'IPv4 endpoint, valid keys, and no custom hooks.') from None
    for key in ('DNS', 'SaveConfig'):
        config.remove_option('Interface', key)
    peer['AllowedIPs'] = ', '.join(cidrs)
    output = io.StringIO()
    config.write(output)
    return output.getvalue(), endpoint, secrets

def state_path(directory):
    root = Path(directory)
    temporary = Path(os.environ['RUNNER_TEMP']).resolve()
    if (root.is_symlink() or root.resolve().parent != temporary or
            not root.name.startswith('wireguard-action-')):
        raise ActionError('Invalid private state directory.')
    return root

def save_state(root, state):
    (root / 'action-state.json').write_text(json.dumps(state))

def interface_name_file(name):
    return Path('/var/run/wireguard/' + name + '.name')

def disconnect(directory, final=True):
    diagnostic('Stage: disconnect and remove private state.')
    root = state_path(directory)
    if not root.exists():
        diagnostic('WireGuard state already removed; cleanup is complete.')
        return
    manifest = root / 'action-state.json'
    succeeded = False
    try:
        if manifest.exists():
            state = json.loads(manifest.read_text())
            name = state.get('name', '')
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,14}', name):
                raise ActionError('Invalid saved interface name.')
            if state.get('attempted') and interface_name_file(name).exists():
                config = root / (name + '.conf')
                secrets = []
                if config.exists():
                    secrets = re.findall(r'(?im)^\s*(?:PrivateKey|PresharedKey)\s*=\s*(\S+)',
                                         config.read_text())
                bins = state['wireguard_bin']
                run('sudo', '-n', 'env', 'PATH=' + bins + ':' + os.environ['PATH'],
                    str(Path(bins) / 'wg-quick'), 'down', str(config),
                    secrets=secrets, log=root / 'wireguard.log')
                diagnostic('WireGuard disconnected.')
        succeeded = True
    finally:

        if succeeded or final:
            shutil.rmtree(root)

def connect(directory):

    raw = os.environ.pop('INPUT_CONFIG', '')
    diagnostic('Stage: validate runner and private configuration.')
    if platform.system() != 'Darwin':
        raise ActionError('This action currently supports macOS runners only.')
    name = 'ciwg'
    if interface_name_file(name).exists():
        raise ActionError('Interface name is already in use; refusing to reuse or stop it.')
    root = state_path(directory)
    state = {'name': name, 'attempted': False}
    save_state(root, state)
    parse_config(raw, [])
    diagnostic('Stage: install WireGuard tools.')
    run('brew', 'install', 'wireguard-tools', timeout=180)
    prefix = run('brew', '--prefix')
    bins = str(Path(prefix) / 'bin')
    if any(not (Path(bins) / binary).is_file() for binary in ('wg', 'wg-quick', 'wireguard-go', 'bash')):
        raise ActionError('Required Homebrew WireGuard tools or Bash are unavailable.')
    diagnostic('Installed versions:\n' + run('brew', 'list', '--versions', 'wireguard-tools',
                                            'wireguard-go', 'bash', 'ncurses'))
    state['wireguard_bin'] = bins
    save_state(root, state)
    diagnostic('Stage: record normal Internet default route.')
    default = route('default')
    if default.get('interface', '').startswith('utun'):
        raise ActionError('Runner already has a VPN default route.')
    diagnostic('Stage: record normal Internet public IPv4 address.')
    public_ip = run('curl', '-4', '--noproxy', '*', '--fail', '--silent', '--show-error',
                    '--max-time', '15', 'https://checkip.amazonaws.com')
    if not ipaddress.IPv4Address(public_ip).is_global:
        raise ActionError('Invalid normal Internet control response.')
    baseline = {'public_ip': public_ip, 'interface': default['interface'], 'gateway': default['gateway']}
    (root / 'baseline.json').write_text(json.dumps(baseline))
    diagnostic('Stage: fetch GitHub metadata over HTTPS.')
    request = urllib.request.Request('https://api.github.com/meta',
                                     headers={'User-Agent': 'wireguard-connect-action'})

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=20) as response:
        metadata = json.load(response)
    diagnostic('Stage: validate GitHub IPv4 ranges and prepare private tunnel files.')
    cidrs = github_ranges(metadata)
    sanitized, endpoint, secrets = parse_config(raw, cidrs)
    (root / 'github-cidrs.json').write_text(json.dumps(cidrs))
    (root / 'vpn-endpoint.txt').write_text(endpoint)
    config = root / (name + '.conf')
    config.write_text(sanitized)
    config.chmod(0o600)
    state['attempted'] = True
    save_state(root, state)
    diagnostic('Stage: bring up WireGuard tunnel.')
    run('sudo', '-n', 'env', 'PATH=' + bins + ':' + os.environ['PATH'],
        str(Path(bins) / 'wg-quick'), 'up', str(config), timeout=45,
        secrets=secrets, log=root / 'wireguard.log')
    interface = run('sudo', '-n', 'cat', str(interface_name_file(name)))
    if not re.fullmatch(r'utun\d+', interface):
        raise ActionError('Unexpected macOS tunnel interface.')
    diagnostic('Stage: verify GitHub IPv4 routes and HTTPS.')
    for host in ('github.com', 'api.github.com'):
        addresses = {entry[4][0] for entry in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)}
        if not addresses:
            raise ActionError('GitHub hostname did not resolve to IPv4.')
        for address in addresses:
            if (not any(ipaddress.IPv4Address(address) in ipaddress.IPv4Network(cidr) for cidr in cidrs)
                    or route(address).get('interface') != interface):
                raise ActionError('GitHub IPv4 route does not use the expected tunnel.')
        run('curl', '-4', '--noproxy', '*', '--fail', '--silent', '--show-error',
            '--max-time', '15', '--output', '/dev/null', 'https://' + host)
    diagnostic('Stage: verify authenticated WireGuard handshake.')
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        lines = run('sudo', '-n', str(Path(bins) / 'wg'), 'show', interface, 'latest-handshakes').splitlines()
        if len(lines) == 1:
            stamp = int(lines[0].split()[1])
            if stamp and 0 <= time.time() - stamp < 180:
                break
        time.sleep(1)
    else:
        raise ActionError('No recent authenticated WireGuard handshake.')
    diagnostic('Stage: verify unchanged normal Internet default route.')
    current = route('default')
    if any(current.get(key) != baseline[key] for key in ('interface', 'gateway')):
        raise ActionError('WireGuard changed the normal Internet default route.')
    diagnostic('Stage: verify unchanged normal Internet public IPv4 address.')
    after_ip = run('curl', '-4', '--noproxy', '*', '--fail', '--silent', '--show-error',
                   '--max-time', '15', 'https://checkip.amazonaws.com')
    if after_ip != public_ip:
        raise ActionError('Normal Internet egress changed after connecting.')
    diagnostic('WireGuard connected: GitHub IPv4 routes, HTTPS, handshake and normal Internet verified.')
    return {'state-directory': str(root), 'interface': interface,
            'wireguard-bin': bins}

def main():
    os.umask(0o077)
    def interrupted(signum, frame):
        raise ActionError('WireGuard operation interrupted.')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    operation, directory = sys.argv[1:]
    try:
        if operation == 'connect':
            result = connect(directory)
            print(json.dumps(result))
        elif operation == 'disconnect':
            os.environ.pop('INPUT_CONFIG', None)
            disconnect(directory)
        else:
            raise ActionError('Invalid lifecycle operation.')
    except Exception as error:

        diagnostic(failure_detail(error))
        if operation == 'connect':
            try:
                disconnect(directory, final=False)
            except Exception as cleanup_error:
                diagnostic('Immediate cleanup failed; the post action will attempt cleanup again. ' +
                           failure_detail(cleanup_error))
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
