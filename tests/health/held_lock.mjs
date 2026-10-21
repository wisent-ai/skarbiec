#!/usr/bin/env node
// Invoked by held_lock.sh in its isolated vault and keyring. Drives the real
// listener: a readiness read with nothing held, then a real gpg that takes
// the keyring lock and keeps it (`--lock-multiple` with its input left open),
// then one readiness read whose canary decrypt queues behind that lock, then
// the readiness read that must answer 503 naming the holder, then the
// holder's end and the queued read's completion.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { constants } from 'node:http2';
import { existsSync, readFileSync, watch, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function required(name) {
  assert.ok(process.env[name]?.trim(), `${name} is required`);
  return process.env[name];
}
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const binary = resolve(required('SKARBIEC'));
const keyring = resolve(required('GNUPGHOME'));
const reportDirectory = resolve(required('SKARBIEC_TEST_REPORT_DIR'));
const report = { revision: required('SKARBIEC_TEST_SOURCE_REVISION'), binary,
  binarySha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
  requests: [], serverOutput: [], passed: false };
const { HTTP_STATUS_OK, HTTP_STATUS_SERVICE_UNAVAILABLE } = constants;
// The lock files GnuPG keeps beside the key databases of this home.
const locks = ['public-keys.d/pubring.db.lock', 'pubring.kbx.lock'].map(name => join(keyring, name));
const args = ['serve', '--port', required('SKARBIEC_TEST_HTTP_PORT')];
const child = spawn(binary, args, { cwd: repo, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
const closed = new Promise(resolveClose => child.once('close', (status, signal) => {
  report.serverExit = { status, signal };
  resolveClose();
}));
const ready = new Promise((resolveReady, rejectReady) => {
  child.once('error', rejectReady);
  child.once('exit', (status, signal) => rejectReady(new Error(
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
        if (match) resolveReady(new URL(match.groups.address));
      }
    });
  }
});
const yieldOnce = () => new Promise(next => setImmediate(next));
// Whether the listener has a gpg child now, as the process table says.
function gpgChildOfListener() {
  const answer = spawnSync('pgrep', ['-P', String(child.pid), 'gpg'], { encoding: 'utf8' });
  return answer.stdout.trim() !== '';
}
let holder;
try {
  const address = await ready;
  async function readiness(label) {
    const response = await fetch(new URL('/readyz', address));
    const text = await response.text();
    report.requests.push({ label, status: response.status, text });
    return { status: response.status, body: JSON.parse(text) };
  }

  const open = await readiness('nothing held');
  assert.equal(open.status, HTTP_STATUS_OK, `readiness with nothing held: ${JSON.stringify(open.body)}`);
  assert.ok(open.body.ok, 'readiness with nothing held must pass');

  // A real gpg takes the keyring lock to import the owner's own public key
  // and, with --lock-multiple and its input left open, keeps it.
  const exported = spawnSync('gpg', ['--homedir', keyring, '--batch', '--export', '--armor'], { encoding: 'utf8' });
  assert.ok(!exported.status && !exported.error, `exporting the owner's public key: ${exported.stderr}`);
  holder = spawn('gpg', ['--homedir', keyring, '--batch', '--yes', '--lock-multiple', '--import'],
    { stdio: ['pipe', 'pipe', 'pipe'] });
  report.holder = { pid: holder.pid, stderr: '' };
  holder.stderr.on('data', chunk => { report.holder.stderr += chunk.toString(); });
  holder.stdin.write(exported.stdout);
  // The lock appears as a file in the keyring; the wait ends when it does,
  // or fails when the holding gpg ends first.
  await new Promise((tookLock, endedFirst) => {
    const watcher = watch(keyring, { recursive: true }, () => {
      if (locks.some(existsSync)) {
        watcher.close();
        tookLock();
      }
    });
    holder.once('exit', (status, signal) => {
      watcher.close();
      endedFirst(new Error(`the holding gpg ended (${status ?? signal}) before taking the lock: ${report.holder.stderr}`));
    });
    if (locks.some(existsSync)) {
      watcher.close();
      tookLock();
    }
  });
  report.holder.lock = locks.find(existsSync);

  // The decrypt of this read queues behind the held lock; it is awaited only
  // after the holder ends. Until its gpg child is in the process table, the
  // read must still be open: an answer before it means the read never queued.
  const queued = readiness('queued behind the held lock');
  let queuedEnded = false;
  const ended = () => { queuedEnded = true; };
  queued.then(ended, ended);
  while (!gpgChildOfListener()) {
    assert.ok(!queuedEnded, `the queued read answered before its gpg child ran: ${JSON.stringify(report.requests.at(-1))}`);
    await yieldOnce();
  }
  const refused = await readiness('while the lock is held');
  assert.equal(refused.status, HTTP_STATUS_SERVICE_UNAVAILABLE, `readiness behind a held lock: ${JSON.stringify(refused.body)}`);
  assert.equal(refused.body.ok, false);
  assert.equal(refused.body.error_code, 'infra_down');
  assert.match(refused.body.detail, /keyring lock is held/, refused.body.detail);
  assert.ok(refused.body.detail.includes(String(holder.pid)),
    `the refusal does not name the holder's pid ${holder.pid}: ${refused.body.detail}`);

  holder.kill('SIGTERM');
  const completed = await queued;
  assert.equal(completed.status, HTTP_STATUS_OK, `the queued read after the holder ended: ${JSON.stringify(completed.body)}`);
  report.passed = true;
} finally {
  if (holder && holder.exitCode === null) holder.kill('SIGKILL');
  child.kill('SIGTERM');
  await closed;
  writeFileSync(join(reportDirectory, 'held_lock.report.json'), JSON.stringify(report, undefined, '  '));
}
