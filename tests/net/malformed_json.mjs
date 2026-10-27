#!/usr/bin/env node
// Real loopback HTTP refusal journey against an isolated Skarbiec vault.
// Supply the committed source revision, its binary and digest, and a free port.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { constants as fsConstants, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { constants as httpStatus } from 'node:http2';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function required(name) {
  assert.ok(process.env[name]?.trim(), `${name} is required`);
  return process.env[name];
}
function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const binary = resolve(required('SKARBIEC'));
const revision = required('SKARBIEC_TEST_SOURCE_REVISION');
const binarySha256 = digest(readFileSync(binary));
assert.equal(binarySha256, required('SKARBIEC_TEST_BINARY_SHA256'));
const source = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' });
assert.equal(source.status, 0, source.stderr);
assert.equal(source.stdout.trim(), revision);
const tracked = spawnSync('git', ['ls-files', '--error-unmatch', 'tests/net/malformed_json.mjs'],
  { cwd: repo, encoding: 'utf8' });
assert.equal(tracked.status, source.status, 'qualification source must be tracked by its revision');
const clean = spawnSync('git', ['diff', '--quiet', 'HEAD'], { cwd: repo, encoding: 'utf8' });
assert.equal(clean.status, source.status, 'source has uncommitted tracked or staged changes');
const base = join(repo, 'target/real-tests/net');
mkdirSync(base, { recursive: true });
const root = mkdtempSync(join(base, 'malformed-json-'));
const keyring = join(root, 'gnupg');
mkdirSync(keyring, { mode: fsConstants.S_IRWXU });
const vault = join(root, 'vault.json');
const env = { ...process.env, GNUPGHOME: keyring, SKARBIEC_VAULT_FILE: vault,
  SKARBIEC_AUDIT_FILE: join(root, 'audit.jsonl') };
const report = { revision, binary, binarySha256,
  testSha256: digest(readFileSync(fileURLToPath(import.meta.url))),
  commands: [], requests: [], serverOutput: [], passed: false };
let child;
let closed;
try {
  const initArgs = ['init', `malformed-json-owner-${randomUUID()}`];
  const init = spawnSync(binary, initArgs, { cwd: repo, env, encoding: 'utf8' });
  report.commands.push({ program: binary, args: initArgs, status: init.status,
    signal: init.signal, stdout: init.stdout, stderr: init.stderr, error: init.error?.message });
  assert.ifError(init.error);
  assert.equal(init.status, source.status, `isolated vault init: ${init.stderr}`);
  const original = readFileSync(vault);
  const port = required('SKARBIEC_TEST_HTTP_PORT');
  const args = ['serve', '--port', port];
  child = spawn(binary, args, { cwd: repo, env, stdio: ['ignore', 'pipe', 'pipe'] });
  report.commands.push({ program: binary, args });
  closed = new Promise(done => child.once('close', (status, signal) => {
    report.serverExit = { status, signal };
    done();
  }));
  const ready = new Promise((done, fail) => {
    child.once('error', fail);
    child.once('exit', (status, signal) => fail(new Error(
      `Skarbiec exited before readiness: ${status ?? signal}; ${report.serverOutput.join('')}`)));
    for (const stream of [child.stdout, child.stderr]) {
      let pending = '';
      stream.on('data', chunk => {
        const text = chunk.toString();
        report.serverOutput.push(text);
        pending += text;
        const lines = pending.split('\n');
        pending = lines.pop();
        for (const line of lines) {
          const match = line.match(/listening on (?<address>http:\/\/\S+)/);
          if (match) done(new URL(match.groups.address));
        }
      });
    }
  });
  const address = await ready;
  assert.equal(address.port, port, 'qualification must reach its isolated listener');
  async function request(label, body) {
    const response = await fetch(new URL('/v1/items/read', address), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
    });
    const text = await response.text();
    report.requests.push({ label, path: '/v1/items/read', status: response.status, text });
    return { status: response.status, body: JSON.parse(text) };
  }
  const malformedBody = '{"id":';
  const malformed = await request('truncated JSON', malformedBody);
  assert.equal(malformed.status, httpStatus.HTTP_STATUS_BAD_REQUEST);
  assert.match(malformed.body.error, /the request body is not JSON/);
  assert.ok(malformed.body.error.includes(`${Buffer.byteLength(malformedBody)} bytes`));
  assert.ok(!malformed.body.error.includes('id required'), 'parse failure must not become a missing-field refusal');
  const missing = await request('valid JSON without id', JSON.stringify({ field: 'value' }));
  assert.equal(missing.status, httpStatus.HTTP_STATUS_BAD_REQUEST);
  assert.equal(missing.body.error, 'id required');
  const unauthorized = await request('valid JSON without grant', JSON.stringify({ id: 'absent', field: 'value' }));
  assert.equal(unauthorized.status, httpStatus.HTTP_STATUS_FORBIDDEN);
  assert.equal(unauthorized.body.error, 'consumer not authorized to read item field');
  const final = readFileSync(vault);
  assert.deepEqual(final, original, 'refused reads must not change the isolated vault');
  report.observedFinalState = { vaultSha256: digest(final), unchanged: true,
    malformedCause: malformed.body.error };
  report.passed = true;
} catch (error) {
  report.failure = error.stack ?? String(error);
  throw error;
} finally {
  if (child) {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  }
  const cleanup = spawnSync('gpgconf', ['--homedir', keyring, '--kill', 'all'],
    { cwd: repo, env, encoding: 'utf8' });
  report.commands.push({ program: 'gpgconf', args: ['--homedir', keyring, '--kill', 'all'],
    status: cleanup.status, stderr: cleanup.stderr, error: cleanup.error?.message });
  if (cleanup.status !== source.status || cleanup.error) {
    report.passed = false;
    report.cleanupFailure = cleanup.error?.message ?? cleanup.stderr;
  }
  rmSync(keyring, { recursive: true, force: true });
  writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, '\t'));
  assert.equal(report.passed, true, `malformed JSON journey report: ${join(root, 'report.json')}`);
}
