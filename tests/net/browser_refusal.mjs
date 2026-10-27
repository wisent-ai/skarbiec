#!/usr/bin/env node
// Real loopback journey: no route answers a web page. Against an isolated
// Skarbiec vault and listener it sends what a browser sends — an Origin, a
// cross-site Sec-Fetch-Site, a rebinding page's foreign Host — to a read and
// to an operator mutation, and checks each is refused 403 with its reason and
// that the vault file is unchanged; the same requests without those headers,
// as a local program sends them, are answered.
// Supply the committed source revision, its binary and digest, and a free port.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { constants as fsConstants, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
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
// A process succeeded when it exited with status zero
// (https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_08_02);
// git's own success is that status, compared against below.
const source = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' });
assert.ok(!source.error && source.signal === null && !source.status, `git rev-parse HEAD: ${source.stderr}`);
const succeeded = source.status;
assert.equal(source.stdout.trim(), revision);
const clean = spawnSync('git', ['diff', '--quiet', 'HEAD'], { cwd: repo, encoding: 'utf8' });
assert.equal(clean.status, succeeded, 'source has uncommitted tracked or staged changes');
const base = join(repo, 'target/real-tests/net');
mkdirSync(base, { recursive: true });
const root = mkdtempSync(join(base, 'browser-refusal-'));
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

function send(address, label, path, headers, body) {
  return new Promise((done, fail) => {
    const outgoing = httpRequest({ host: address.hostname, port: address.port, path, method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...headers } },
    (response) => {
      let text = '';
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => {
        report.requests.push({ label, path, headers, status: response.statusCode, text });
        done({ status: response.statusCode, body: JSON.parse(text) });
      });
    });
    outgoing.once('error', fail);
    outgoing.end(body);
  });
}

try {
  const initArgs = ['init', `browser-refusal-owner-${randomUUID()}`];
  const init = spawnSync(binary, initArgs, { cwd: repo, env, encoding: 'utf8' });
  report.commands.push({ program: binary, args: initArgs, status: init.status, stderr: init.stderr });
  assert.equal(init.status, succeeded, `isolated vault init: ${init.stderr}`);
  const original = readFileSync(vault);
  const port = required('SKARBIEC_TEST_HTTP_PORT');
  const args = ['serve', '--port', port];
  child = spawn(binary, args, { cwd: repo, env, stdio: ['ignore', 'pipe', 'pipe'] });
  report.commands.push({ program: binary, args });
  closed = new Promise((done) => child.once('close', (status, signal) => {
    report.serverExit = { status, signal };
    done();
  }));
  const address = await new Promise((done, fail) => {
    child.once('error', fail);
    child.once('exit', (status, signal) => fail(new Error(
      `Skarbiec exited before readiness: ${status ?? signal}; ${report.serverOutput.join('')}`)));
    for (const stream of [child.stdout, child.stderr]) {
      let pending = '';
      stream.on('data', (chunk) => {
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
  assert.equal(address.port, port, 'qualification must reach its isolated listener');

  const trash = JSON.stringify({ positionals: [`absent-${randomUUID()}`], flags: {} });
  const browserLike = [
    ['a cross-site page', { origin: 'https://attacker.example' }, /web page/],
    ['a page with only Sec-Fetch-Site', { 'sec-fetch-site': 'cross-site' }, /Sec-Fetch-Site/],
    ['a DNS-rebinding page', { host: `attacker.example:${port}` }, /not a loopback address/],
  ];
  for (const [label, headers, reason] of browserLike) {
    for (const path of ['/v1/operator/items/trash', '/v1/operator/items']) {
      const refused = await send(address, label, path, headers, trash);
      assert.equal(refused.status, httpStatus.HTTP_STATUS_FORBIDDEN, `${label} reached ${path}`);
      assert.match(refused.body.error, reason);
    }
  }
  assert.deepEqual(readFileSync(vault), original, 'a refused browser request changed the vault');

  const local = await send(address, 'a local program', '/v1/operator/items', {}, JSON.stringify({}));
  assert.equal(local.status, httpStatus.HTTP_STATUS_OK, `a local program was refused: ${JSON.stringify(local.body)}`);
  report.observedFinalState = { vaultSha256: digest(readFileSync(vault)), unchanged: true };
  report.passed = true;
} catch (error) {
  report.failure = error.stack ?? String(error);
  throw error;
} finally {
  if (child) {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  }
  const cleanup = spawnSync('gpgconf', ['--homedir', keyring, '--kill', 'all'], { cwd: repo, env, encoding: 'utf8' });
  report.commands.push({ program: 'gpgconf', args: ['--homedir', keyring, '--kill', 'all'], status: cleanup.status, stderr: cleanup.stderr });
  rmSync(keyring, { recursive: true, force: true });
  writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, '\t'));
  assert.equal(report.passed, true, `browser refusal journey report: ${join(root, 'report.json')}`);
}
