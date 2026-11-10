const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { spawnSync } = require('node:child_process');

function write(file, name, value) {
  const delimiter = randomUUID();
  fs.appendFileSync(file, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
}

try {
  const operation = process.env.STATE_directory ? 'disconnect' :
    (process.env.INPUT_OPERATION || 'connect').trim();
  let directory = process.env.STATE_directory || process.env['INPUT_STATE-DIRECTORY'];
  if (operation === 'connect') {
    if (!process.env.INPUT_CONFIG?.trim()) throw new Error();
    directory = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP, 'wireguard-action-'));
    fs.chmodSync(directory, 0o700);
    write(process.env.GITHUB_STATE, 'directory', directory);
    write(process.env.GITHUB_OUTPUT, 'state-directory', directory);
  } else if (operation !== 'disconnect' || !directory) {
    throw new Error();
  }
  const result = spawnSync('python3', [path.join(__dirname, 'vpn.py'), operation, directory], {
    encoding: 'utf8',
    timeout: operation === 'connect' ? 300000 : 60000,
    maxBuffer: 1024 * 1024,
    env: process.env,
  });
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error || result.status !== 0) throw new Error();
  if (operation === 'connect') {
    for (const [name, value] of Object.entries(JSON.parse(result.stdout))) {
      write(process.env.GITHUB_OUTPUT, name, value);
    }
  }
} catch {
  process.stderr.write('::error::WireGuard action failed.\n');
  process.exitCode = 1;
}
