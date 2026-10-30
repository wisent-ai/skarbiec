#!/usr/bin/env node
// Invoked by decrypt_pileup.sh in its isolated vault and keyring. Drives the
// real listener with many concurrent `POST /v1/items/read` calls, each of
// which decrypts the item with a real gpg against the fixture's real
// gpg-agent and keyboxd, and reads `/health` throughout:
//  1. agent answering: more reads than the gpg capacity at once; never more
//     gpg children than the capacity, `/health` answers every time, and
//     every read answers its value;
//  2. agent silent (its socket replaced by one that accepts and never
//     greets): reads past the capacity queue, `/health` keeps answering and
//     reports the queue's depth and its oldest wait; callers that close
//     their connections leave no gpg child and no queued run behind, long
//     before the deadline;
//  3. agent still silent: every read answers 503 within the deadline, with
//     a sentence naming the wait, the cause and the fix;
//  4. the silent socket gone: gpg starts one gpg-agent for the home, every
//     read answers its value, and one keyboxd and one gpg-agent serve it.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { availableParallelism } from 'node:os';
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
const item = required('SKARBIEC_TEST_ITEM');
const consumer = required('SKARBIEC_TEST_CONSUMER');
const token = required('SKARBIEC_TEST_TOKEN');
const value = required('SKARBIEC_TEST_VALUE');
const report = { revision: required('SKARBIEC_TEST_SOURCE_REVISION'), binary,
  binarySha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
  phases: {}, health: [], serverOutput: [], passed: false };
// The fixture's deadline: long enough for a healthy decrypt on a loaded
// host, short enough that the journey waits on it once.
const deadlineSeconds = 6;
const capacity = availableParallelism();
const agentSocket = join(keyring, 'S.gpg-agent');
const env = { ...process.env, SKARBIEC_GPG_DEADLINE_SECONDS: String(deadlineSeconds) };
const child = spawn(binary, ['serve', '--port', '0'], { cwd: repo, env, stdio: ['ignore', 'pipe', 'pipe'] });
const closed = new Promise(resolveClose => child.once('close', (status, signal) => {
  report.serverExit = { status, signal };
  resolveClose();
}));
const ready = new Promise((resolveReady, rejectReady) => {
  child.once('error', rejectReady);
  child.once('exit', (status, signal) => rejectReady(new Error(
    `Skarbiec exited before listening: ${status ?? signal}; ${report.serverOutput.join('')}`)));
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
// The gpg children of the listener now, as the process table says.
function gpgChildren() {
  const answer = spawnSync('pgrep', ['-x', '-P', String(child.pid), 'gpg'], { encoding: 'utf8' });
  return answer.stdout.trim().split('\n').filter(line => line !== '');
}
// The daemons serving this home, as the process table says.
function daemonsOfHome(name) {
  const answer = spawnSync('pgrep', ['-f', `${name} --homedir ${keyring}`], { encoding: 'utf8' });
  return answer.stdout.trim().split('\n').filter(line => line !== '');
}
const pause = milliseconds => new Promise(next => setTimeout(next, milliseconds));
let silent;
let maxChildren = 0;
try {
  const address = await ready;
  async function health(label) {
    const started = performance.now();
    const response = await fetch(new URL('/health', address), { signal: AbortSignal.timeout(deadlineSeconds * 1000) });
    const body = await response.json();
    const seconds = (performance.now() - started) / 1000;
    report.health.push({ label, status: response.status, seconds, crypto: body.crypto });
    assert.equal(response.status, 200, `${label}: /health answered ${response.status}: ${JSON.stringify(body)}`);
    assert.equal(body.ok, true, `${label}: /health was not ok: ${JSON.stringify(body)}`);
    assert.equal(body.canaries, undefined, `${label}: /health decrypted canaries`);
    return { body, seconds };
  }
  // One read; a connection the listener ended without an answer is recorded
  // as that, with its cause, so the assertion that follows names it.
  function read(label, signal) {
    const started = performance.now();
    return fetch(new URL('/v1/items/read', address), {
      method: 'POST', signal,
      headers: { 'content-type': 'application/json', 'x-consumer': consumer, authorization: `Bearer ${token}` },
      body: JSON.stringify({ id: item, field: 'value' }),
    }).then(async response => ({ label, status: response.status, body: await response.json(),
      seconds: (performance.now() - started) / 1000 }))
      .catch(error => ({ label, status: 'no answer', body: { error: `${error.name}: ${error.message}: ${error.cause?.message}` },
        seconds: (performance.now() - started) / 1000 }));
  }
  // Read /health and the process table until `done` holds, the reads
  // settle, or `within` seconds pass; every /health must answer.
  async function watch(label, settled, done, within) {
    const until = performance.now() + within * 1000;
    let last;
    while (performance.now() < until) {
      const children = gpgChildren().length;
      maxChildren = Math.max(maxChildren, children);
      last = await health(label);
      last.children = children;
      if (done(last) || settled()) return last;
      await pause(50);
    }
    return last;
  }

  const first = await health('before any read');
  assert.equal(first.body.crypto.gpg_capacity, capacity,
    `the gpg capacity is not this host's available parallelism: ${JSON.stringify(first.body.crypto)}`);
  assert.equal(first.body.crypto.gpg_deadline_seconds, deadlineSeconds);
  assert.equal(first.body.crypto.gpg_queued, 0);
  assert.equal(first.body.crypto.gpg_oldest_wait_seconds, null);

  // 1. Agent answering: four times the capacity at once.
  {
    let pending = capacity * 4;
    const reads = Array.from({ length: pending }, (_, index) => read(`answering ${index}`).finally(() => { pending -= 1; }));
    await watch('agent answering', () => pending === 0, () => false, deadlineSeconds * 4);
    const answers = await Promise.all(reads);
    report.phases.answering = { reads: answers.map(({ label, status, seconds }) => ({ label, status, seconds })), maxChildren };
    for (const answer of answers) {
      assert.equal(answer.status, 200, `${answer.label} with the agent answering: ${JSON.stringify(answer.body)}`);
      assert.equal(answer.body.value, value, `${answer.label} answered another value`);
    }
    assert.ok(maxChildren <= capacity, `the listener ran ${maxChildren} gpg children at once, above its capacity ${capacity}`);
  }

  // The real agent is ended and its socket replaced by one that accepts every
  // connection and never greets: a gpg that asks it for a key waits forever.
  const killed = spawnSync('gpgconf', ['--homedir', keyring, '--kill', 'gpg-agent'], { encoding: 'utf8' });
  assert.ok(!killed.status && !killed.error, `ending the real agent: ${killed.stderr}`);
  if (existsSync(agentSocket)) unlinkSync(agentSocket);
  const held = [];
  silent = createServer(connection => { held.push(connection); });
  await new Promise((listening, failed) => silent.once('error', failed).listen(agentSocket, listening));

  // 2. Agent silent, callers that leave: twice the capacity, abandoned once
  // the capacity runs and the rest queue.
  {
    const abort = new AbortController();
    const total = capacity * 2;
    const sent = performance.now();
    const reads = Array.from({ length: total }, (_, index) => read(`abandoned ${index}`, abort.signal).catch(error => ({ aborted: error.name })));
    const full = await watch('callers waiting on a silent agent', () => false,
      ({ body }) => body.crypto.gpg_active === capacity && body.crypto.gpg_queued === total - capacity, deadlineSeconds / 2);
    report.phases.abandoned = { full };
    assert.equal(full.body.crypto.gpg_active, capacity, `the silent agent did not hold the capacity: ${JSON.stringify(full.body.crypto)}`);
    assert.equal(full.body.crypto.gpg_queued, total - capacity, `the reads past the capacity did not queue: ${JSON.stringify(full.body.crypto)}`);
    assert.ok(full.body.crypto.gpg_oldest_wait_seconds > 0, `the queue reports no oldest wait: ${JSON.stringify(full.body.crypto)}`);
    assert.ok(full.children <= capacity, `${full.children} gpg children ran past the capacity ${capacity}`);
    assert.ok(full.seconds < 1, `/health took ${full.seconds}s while every gpg run waited`);
    abort.abort();
    await Promise.all(reads);
    const emptied = await watch('after the callers left', () => false,
      ({ body, children }) => body.crypto.gpg_active === 0 && body.crypto.gpg_queued === 0 && children === 0, deadlineSeconds);
    const after = (performance.now() - sent) / 1000;
    report.phases.abandoned.emptied = { ...emptied, secondsSinceSent: after };
    assert.equal(emptied.body.crypto.gpg_queued, 0, `queued runs outlived their callers: ${JSON.stringify(emptied.body.crypto)}`);
    assert.equal(emptied.body.crypto.gpg_active, 0, `running gpg outlived its callers: ${JSON.stringify(emptied.body.crypto)}`);
    assert.equal(emptied.children, 0, 'gpg children outlived their callers');
    assert.ok(after < deadlineSeconds, `the abandoned runs ended ${after}s after they were sent, not before the ${deadlineSeconds}s deadline`);
  }

  // 3. Agent silent, callers that wait: three times the capacity; each
  // answers 503 within the deadline, naming the wait, the cause and the fix.
  {
    let pending = capacity * 3;
    const reads = Array.from({ length: pending }, (_, index) => read(`deadline ${index}`).finally(() => { pending -= 1; }));
    const during = await watch('reads waiting for the deadline', () => pending === 0,
      ({ body }) => body.crypto.gpg_queued === capacity * 2, deadlineSeconds / 2);
    assert.equal(during.body.crypto.gpg_queued, capacity * 2, `the reads did not queue: ${JSON.stringify(during.body.crypto)}`);
    await watch('reads past the deadline', () => pending === 0, () => false, deadlineSeconds * 2);
    const answers = await Promise.all(reads);
    report.phases.deadline = { during, reads: answers.map(({ label, status, seconds, body }) => ({ label, status, seconds, detail: body.detail })) };
    let ended = 0;
    let queued = 0;
    for (const answer of answers) {
      assert.equal(answer.status, 503, `${answer.label} behind a silent agent: ${JSON.stringify(answer.body)}`);
      assert.equal(answer.body.error_code, 'infra_down');
      assert.equal(answer.body.value, undefined, `${answer.label} answered a value`);
      assert.ok(answer.seconds < deadlineSeconds + 1, `${answer.label} answered after ${answer.seconds}s, past the ${deadlineSeconds}s deadline`);
      const { detail } = answer.body;
      if (/was ended after .* because its deadline \(SKARBIEC_GPG_DEADLINE_SECONDS=6\) passed before gpg answered/.test(detail)) {
        assert.match(detail, /gpg-agent or keyboxd did not answer in time, or another process holds the keyring lock/, detail);
        assert.match(detail, /run `skarbiec maintain` to replace daemons that stopped answering, or raise SKARBIEC_GPG_DEADLINE_SECONDS/, detail);
        ended += 1;
      } else {
        assert.match(detail, new RegExp(`waited .* for one of the ${capacity} gpg runs this host runs at once and its deadline \\(6s, SKARBIEC_GPG_DEADLINE_SECONDS=6\\) passed first, with \\d+ gpg run\\(s\\) queued ahead of it and \\d+ running`), detail);
        assert.match(detail, /GET \/health names them under crypto\.gpg_waiting_on_agent and gives the queue/, detail);
        assert.match(detail, /run `skarbiec maintain` to replace daemons that stopped answering, or raise SKARBIEC_GPG_DEADLINE_SECONDS/, detail);
        queued += 1;
      }
    }
    // Deadlines fall a few milliseconds apart, so a queued run whose
    // deadline had not yet passed when a running one was ended may start
    // and be ended running in its turn; every read is one of the two.
    assert.ok(ended >= capacity, `${ended} reads were ended running, fewer than the capacity ${capacity}`);
    assert.ok(queued >= 1, `no read left the queue at its deadline: ${ended} were ended running`);
    assert.equal(ended + queued, capacity * 3);
    const after = await health('after the deadline');
    assert.equal(after.body.crypto.gpg_active, 0);
    assert.equal(after.body.crypto.gpg_queued, 0);
    assert.equal(gpgChildren().length, 0, 'gpg children outlived their deadline');
  }

  // 4. The silent socket ends; gpg starts a fresh agent and every read
  // answers again.
  for (const connection of held) connection.destroy();
  await new Promise(done => silent.close(done));
  silent = undefined;
  {
    const answers = await Promise.all(Array.from({ length: capacity * 2 }, (_, index) => read(`recovered ${index}`)));
    report.phases.recovered = { reads: answers.map(({ label, status, seconds }) => ({ label, status, seconds })) };
    for (const answer of answers) {
      assert.equal(answer.status, 200, `${answer.label} after the agent came back: ${JSON.stringify(answer.body)}`);
      assert.equal(answer.body.value, value);
    }
    const agents = daemonsOfHome('gpg-agent');
    const keyboxds = daemonsOfHome('keyboxd');
    report.phases.recovered.daemons = { agents, keyboxds };
    assert.equal(agents.length, 1, `gpg-agents serving the home: ${JSON.stringify(agents)}`);
    assert.equal(keyboxds.length, 1, `keyboxd daemons serving the home: ${JSON.stringify(keyboxds)}`);
  }
  report.maxChildren = maxChildren;
  assert.ok(maxChildren <= capacity, `the listener ran ${maxChildren} gpg children at once, above its capacity ${capacity}`);
  report.passed = true;
} finally {
  if (silent) await new Promise(done => silent.close(done));
  child.kill('SIGTERM');
  await closed;
  writeFileSync(join(reportDirectory, 'decrypt_pileup.report.json'), JSON.stringify(report, undefined, '  '));
}
