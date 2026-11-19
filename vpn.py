import base64
import configparser
import datetime
import http.client
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
import urllib.error
import urllib.request

DOWNLOAD_BUDGET_SECONDS = 45
DOWNLOAD_TIMEOUT_SECONDS = 10
RETRY_DELAY_SECONDS = 2

class ActionError(Exception):
    pass

class ActionInterrupted(ActionError):
    pass

class DownloadBudgetExpired(ActionError):
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

def internet_public_ip(address):
    value = run('curl', '--disable', '-4', '--noproxy', '*', '--fail', '--silent', '--show-error',
                '--resolve', 'checkip.amazonaws.com:443:' + address,
                '--max-time', '15', 'https://checkip.amazonaws.com')
    try:
        if not ipaddress.IPv4Address(value).is_global:
            raise ValueError()
    except ValueError:
        raise ActionError('Invalid normal Internet control response.') from None
    return value

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
                    if not network.is_global or network.is_multicast or network.prefixlen < 8:
                        raise ValueError()
                    networks.add(network)
        if not networks or len(networks) > 512:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ActionError('Invalid GitHub IPv4 range metadata.') from None
    return [str(network) for network in ipaddress.collapse_addresses(networks)]

def fetch_github_ranges():
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()

    def expired(signum, frame):
        raise DownloadBudgetExpired('GitHub range download time budget exhausted.')

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, DOWNLOAD_BUDGET_SECONDS)
    try:
        return _fetch_github_ranges(started + DOWNLOAD_BUDGET_SECONDS)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            remaining = max(0.001, previous_timer[0] - (time.monotonic() - started))
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_timer[1])

def _fetch_github_ranges(deadline):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def read_json(url):
        request = urllib.request.Request(url, headers={'User-Agent': 'wireguard-connect-action'})
        for attempt in range(2):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DownloadBudgetExpired('GitHub range download time budget exhausted.')
            try:
                with opener.open(request, timeout=min(DOWNLOAD_TIMEOUT_SECONDS, remaining)) as response:
                    raw = response.read(1024 * 1024 + 1)
                break
            except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
                reason = error.reason if isinstance(error, urllib.error.URLError) else error
                retry = isinstance(reason, (TimeoutError, ConnectionError, http.client.HTTPException))
                retry = retry or (isinstance(reason, socket.gaierror) and reason.errno == socket.EAI_AGAIN)
                if isinstance(error, urllib.error.HTTPError):
                    limited = error.headers and (error.headers.get('Retry-After') or error.headers.get('X-RateLimit-Remaining') == '0')
                    retry = error.code in (502, 503, 504) and not limited
                if attempt or not retry or deadline - time.monotonic() <= RETRY_DELAY_SECONDS:
                    raise
                diagnostic('Retrying ' + request.host + ' range download in ' + str(RETRY_DELAY_SECONDS) +
                           ' seconds (' + type(error).__name__ + ').')
                time.sleep(RETRY_DELAY_SECONDS)
        if len(raw) > 1024 * 1024:
            raise ActionError('GitHub range response exceeds the size limit.')
        return json.loads(raw)

    try:
        return github_ranges(read_json('https://api.github.com/meta'))
    except (ActionInterrupted, DownloadBudgetExpired):
        raise
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError, ActionError) as error:
        diagnostic('::warning::GitHub Meta unavailable; attempting public fallback. ' + failure_detail(error))
        if isinstance(error, urllib.error.HTTPError) and error.headers:
            limits = {name: error.headers.get(name) for name in
                      ('X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After')}
            diagnostic('GitHub response limits: ' + json.dumps(limits))

    try:
        snapshot = read_json('https://raw.githubusercontent.com/Truvideo/github-ips/master/github-ipv4.json')
        if (not isinstance(snapshot, dict) or type(snapshot.get('schema_version')) is not int or
                snapshot['schema_version'] != 1 or snapshot.get('source') != 'https://api.github.com/meta'):
            raise ValueError()
        fetched = datetime.datetime.strptime(snapshot['fetched_at'], '%Y-%m-%dT%H:%M:%SZ')
        age = time.time() - fetched.replace(tzinfo=datetime.timezone.utc).timestamp()
        if age < -300 or age > 72 * 60 * 60:
            raise ValueError()
        entries = snapshot['ipv4']
        if (not isinstance(entries, list) or not 10 <= len(entries) <= 512 or
                any(not isinstance(entry, str) or ipaddress.ip_network(entry).version != 4 for entry in entries)):
            raise ValueError()
        cidrs = github_ranges({service: entries for service in ('web', 'api', 'git')})
        if len(cidrs) < 10:
            raise ValueError()
    except (ActionInterrupted, DownloadBudgetExpired):
        raise
    except Exception as error:
        diagnostic('Public GitHub fallback failed: ' + failure_detail(error))
        raise ActionError('No valid GitHub ranges: API failed and fallback is unavailable, invalid or older than 72 hours.') from None
    diagnostic('Using validated public fallback: ' + str(len(cidrs)) +
               ' IPv4 ranges; fetched_at=' + snapshot['fetched_at'])
    return cidrs

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
    diagnostic('Stage: record normal Internet control route and public IPv4 address.')
    addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(
        'checkip.amazonaws.com', None, socket.AF_INET, socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.IPv4Address(address).is_global for address in addresses):
        raise ActionError('Normal Internet control did not resolve to public IPv4 addresses.')
    control_address = addresses[0]
    control = route(control_address)
    if control.get('interface') != default['interface'] or not control.get('gateway'):
        raise ActionError('Normal Internet control does not use the original default interface.')
    control = {key: control[key] for key in ('interface', 'gateway')}
    public_ip = internet_public_ip(control_address)
    diagnostic('Normal Internet before: destination=' + control_address + ', interface=' +
               control['interface'] + ', gateway=' + control['gateway'] + ', public_ip=' + public_ip)
    baseline = {'public_ip': public_ip, 'interface': default['interface'], 'gateway': default['gateway'],
                'control_address': control_address, 'control_route': control}
    (root / 'baseline.json').write_text(json.dumps(baseline))
    diagnostic('Stage: fetch GitHub metadata over HTTPS.')
    cidrs = fetch_github_ranges()
    diagnostic('Stage: validate GitHub IPv4 ranges and prepare private tunnel files.')
    if any(ipaddress.IPv4Address(control_address) in ipaddress.IPv4Network(cidr) for cidr in cidrs):
        raise ActionError('Normal Internet control overlaps the GitHub VPN routes.')
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
    diagnostic('Stage: verify normal Internet control stays on its original route.')
    current_control = route(control_address)
    if any(current_control.get(key) != control[key] for key in ('interface', 'gateway')):
        raise ActionError('WireGuard changed the normal Internet control route.')
    after_ip = internet_public_ip(control_address)
    current_control = route(control_address)
    if any(current_control.get(key) != control[key] for key in ('interface', 'gateway')):
        raise ActionError('Normal Internet control route changed during its HTTPS request.')
    diagnostic('Normal Internet after: destination=' + control_address + ', interface=' +
               current_control['interface'] + ', gateway=' + current_control['gateway'] +
               ', public_ip=' + after_ip)
    if after_ip != public_ip:
        diagnostic('::warning::Normal Internet public IPv4 changed; the control destination, '
                   'interface, gateway and default route remain unchanged.')
    diagnostic('WireGuard connected: GitHub IPv4 routes, HTTPS, handshake and normal Internet verified.')
    return {'state-directory': str(root), 'interface': interface,
            'wireguard-bin': bins}

def main():
    os.umask(0o077)
    def interrupted(signum, frame):
        raise ActionInterrupted('WireGuard operation interrupted.')
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
