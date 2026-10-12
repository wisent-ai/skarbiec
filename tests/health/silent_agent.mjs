#!/usr/bin/env node
// Invoked by silent_agent.sh in its isolated vault and keyring. Drives the real
// listener: a readiness read with the real gpg-agent answering, then the agent
// replaced by a socket that accepts and never answers, then one readiness read
// whose canary decrypt asks that silent agent for its key, then the readiness
// read that must answer 503 naming the waiting gpg child and the status it
// stopped at, and `/health` publishing it under `crypto.gpg_waiting_on_agent`;
// then the silent socket's end, after which the waiting child fails, the vault
// recovers its daemons, retries, and the queued read completes with 200.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { constants } from 'node:http2';
import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
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
// Where gpg finds its agent for this home.
const agentSocket = join(keyring, 'S.gpg-agent');
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
// The gpg children of the listener now, as the process table says.
function gpgChildrenOfListener() {
  const answer = spawnSync('pgrep', ['-P', String(child.pid), 'gpg'], { encoding: 'utf8' });
  return answer.stdout.trim().split('\n').filter(line => line !== '');
}
const some = list => list.some(() => true);
let silent;
try {
  const address = await ready;
  async function readiness(label) {
    const response = await fetch(new URL('/readyz', address));
    const text = await response.text();
    report.requests.push({ label, status: response.status, text });
    return { status: response.status, body: JSON.parse(text) };
  }

  const open = await readiness('agent answering');
  assert.equal(open.status, HTTP_STATUS_OK, `readiness with the agent answering: ${JSON.stringify(open.body)}`);
  assert.ok(open.body.ok, 'readiness with the agent answering must pass');
  assert.deepEqual(open.body.crypto.gpg_waiting_on_agent, [], 'nothing waits on an answering agent');

  // The real agent is ended and its socket replaced by one that accepts every
  // connection and never greets: a gpg that asks it for a key waits forever.
  const killed = spawnSync('gpgconf', ['--homedir', keyring, '--kill', 'gpg-agent'], { encoding: 'utf8' });
  assert.ok(!killed.status && !killed.error, `ending the real agent: ${killed.stderr}`);
  if (existsSync(agentSocket)) unlinkSync(agentSocket);
  const held = [];
  silent = createServer(connection => { held.push(connection); });
  await new Promise((listening, failed) => silent.once('error', failed).listen(agentSocket, listening));
  report.silentAgent = { socket: agentSocket };

  // The decrypt of this read asks the silent agent; it is awaited only after
  // the silent socket ends.
  const queued = readiness('asking the silent agent');
  while (!some(gpgChildrenOfListener()) || !some(held)) {
    await yieldOnce();
  }
  // The child announces its key (ENC_TO) and then hears nothing; the register
  // reads that line as it is written, so the next read is refused at once.
  let refused = await readiness('while the agent is silent');
  while (refused.status === HTTP_STATUS_OK) {
    refused = await readiness('while the agent is silent');
  }
  assert.equal(refused.status, HTTP_STATUS_SERVICE_UNAVAILABLE, `readiness behind a silent agent: ${JSON.stringify(refused.body)}`);
  assert.equal(refused.body.ok, false);
  assert.equal(refused.body.error_code, 'infra_down');
  assert.match(refused.body.detail, /asked gpg-agent for its key without an answer/, refused.body.detail);
  assert.match(refused.body.detail, /stopped at status ENC_TO/, refused.body.detail);
  const waiting = gpgChildrenOfListener();
  assert.ok(waiting.some(pid => refused.body.detail.includes(`pid ${pid}`)),
    `the refusal does not name a waiting gpg child of ${JSON.stringify(waiting)}: ${refused.body.detail}`);
  assert.equal(refused.body.crypto.gpg_waiting_on_agent.length, waiting.length,
    `the health document does not list every waiting child: ${JSON.stringify(refused.body.crypto)}`);

  // The silent socket ends: the waiting child fails on its lost agent, the
  // vault recovers the daemons and retries, and the queued read completes.
  for (const connection of held) connection.destroy();
  await new Promise(done => silent.close(done));
  silent = undefined;
  const completed = await queued;
  assert.equal(completed.status, HTTP_STATUS_OK, `the queued read after the agent came back: ${JSON.stringify(completed.body)}`);
  assert.deepEqual(completed.body.crypto.gpg_waiting_on_agent, [], 'the recovered vault has nothing waiting');
  report.passed = true;
} finally {
  if (silent) await new Promise(done => silent.close(done));
  child.kill('SIGTERM');
  await closed;
  writeFileSync(join(reportDirectory, 'silent_agent.report.json'), JSON.stringify(report, undefined, '  '));
}
