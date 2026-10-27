#!/usr/bin/env node
// Real test of `/readyz` on a vault whose canary item this host cannot
// decrypt, through the built binary on a vault and keyring of its own under
// this checkout's target directory, so the operator's vault and keyring are
// never read or written.
//
// It creates the vault and one note, then seals every item's current
// ciphertext to a key whose secret half lives in another keyring: the state
// of a vault item encrypted to a recipient this host does not hold. `/readyz`
// must answer 503 naming the item and carrying gpg's own sentence for why it
// could not open it; a refusal that names the item alone sends the reader to
// the item instead of to the key it was sealed to.
//
// Supply SKARBIEC, SKARBIEC_TEST_SOURCE_REVISION and SKARBIEC_TEST_HTTP_PORT,
// then run `node tests/health/undecryptable.mjs`.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { constants } from 'node:http2';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function required(name) {
  assert.ok(process.env[name]?.trim(), `${name} is required`);
  return process.env[name];
}
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const binary = resolve(required('SKARBIEC'));
const revision = required('SKARBIEC_TEST_SOURCE_REVISION');
const port = required('SKARBIEC_TEST_HTTP_PORT');
const git = args => spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8' });
assert.equal(git(['rev-parse', 'HEAD']).stdout.trim(), revision,
  'the checkout is not the source revision under qualification');
assert.ok(!git(['diff', '--quiet']).status, 'the source has uncommitted tracked changes');

const run = `${new Date().toISOString().replace(/[-:.]/g, '')}-${process.pid}`;
const root = join(repo, 'target/real-tests/health', run);
const keyring = join(repo, 'target', `g${process.pid}`);
const stranger = join(repo, 'target', `s${process.pid}`);
for (const directory of [root, keyring, stranger]) {
  mkdirSync(directory, { recursive: true });
  // GnuPG refuses a home others can read, as the vault's own files are kept.
  const restricted = spawnSync('chmod', ['go-rwx', directory], { encoding: 'utf8' });
  assert.ok(!restricted.status && !restricted.error, `chmod go-rwx ${directory}: ${restricted.stderr}`);
}
const env = { ...process.env, GNUPGHOME: keyring, SKARBIEC_VAULT_FILE: join(root, 'vault.json'),
  SKARBIEC_AUDIT_FILE: join(root, 'audit.jsonl'), SKARBIEC_TEST_REPORT_DIR: root };
const report = { revision, binary,
  binarySha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
  commands: [], requests: [], serverOutput: [], passed: false };

function skarbiec(args, input) {
  const answer = spawnSync(binary, args, { cwd: repo, env, input, encoding: 'utf8' });
  report.commands.push({ args, status: answer.status, stderr: answer.stderr });
  assert.ok(!answer.status && !answer.error, `skarbiec ${args.join(' ')}: ${answer.stderr}`);
}
function gpg(home, args, input) {
  const answer = spawnSync('gpg', ['--homedir', home, '--batch', ...args], { input, encoding: 'utf8' });
  assert.ok(!answer.status && !answer.error, `gpg ${args.join(' ')}: ${answer.stderr}`);
  return answer.stdout;
}

let child;
let closed;
try {
  skarbiec(['init', `undecryptable-owner-${run}`]);
  const payload = { schema: 'skarbiec.item.v2', kind: 'note', fields: { value: `undecryptable-${run}` }, context: {} };
  skarbiec(['set', `undecryptable-note-${run}`, '--type', 'note'], JSON.stringify(payload));

  // A key whose secret half only the other keyring holds.
  const identity = `stranger-${run}`;
  gpg(stranger, ['--passphrase', '', '--quick-generate-key', identity]);
  const sealed = gpg(stranger, ['--armor', '--trust-model', 'always', '--recipient', identity, '--encrypt'],
    JSON.stringify(payload));
  const vault = JSON.parse(readFileSync(env.SKARBIEC_VAULT_FILE, 'utf8'));
  const items = Object.values(vault.items);
  assert.ok(items.length, 'the vault holds no item to seal away');
  for (const item of items) item.current.ciphertext = sealed;
  writeFileSync(env.SKARBIEC_VAULT_FILE, JSON.stringify(vault, undefined, '  '));

  child = spawn(binary, ['serve', '--port', port], { cwd: repo, env, stdio: ['ignore', 'pipe', 'pipe'] });
  closed = new Promise(resolveClose => child.once('close', (status, signal) => {
    report.serverExit = { status, signal };
    resolveClose();
  }));
  const address = await new Promise((resolveReady, rejectReady) => {
    child.once('error', rejectReady);
    child.once('exit', (status, signal) => rejectReady(new Error(
      `Skarbiec exited before readiness: ${status ?? signal}; ${report.serverOutput.join('')}`)));
    for (const stream of [child.stdout, child.stderr]) {
      stream.on('data', chunk => {
        report.serverOutput.push(chunk.toString());
        const match = report.serverOutput.join('').match(/listening on (?<address>http:\/\/\S+)/);
        if (match) resolveReady(new URL(match.groups.address));
      });
    }
  });

  const response = await fetch(new URL('/readyz', address));
  const text = await response.text();
  report.requests.push({ status: response.status, text });
  const body = JSON.parse(text);
  assert.equal(response.status, constants.HTTP_STATUS_SERVICE_UNAVAILABLE, text);
  assert.equal(body.ok, false);
  assert.equal(body.error_code, 'infra_down');
  assert.match(body.detail, /stored item \S+ cannot be decrypted/, body.detail);
  // gpg's own sentence, one layer below the item: the key it was sealed to
  // is not on this host.
  assert.match(body.detail, /gpg failed/, body.detail);
  assert.match(body.detail, /No secret key/, body.detail);
  report.passed = true;
} finally {
  if (child) {
    child.kill('SIGTERM');
    await closed;
  }
  for (const home of [keyring, stranger]) {
    spawnSync('gpgconf', ['--homedir', home, '--kill', 'all']);
    rmSync(home, { recursive: true, force: true });
  }
  writeFileSync(join(root, 'undecryptable.report.json'), JSON.stringify(report, undefined, '  '));
}
