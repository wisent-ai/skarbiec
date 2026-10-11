#!/usr/bin/env node
// Invoked by group.sh after real CLI issuance in its isolated vault/keyring.
import assert from 'node:assert/strict';
import { constants } from 'node:http2';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { lstatSync, mkdirSync, readFileSync, readlinkSync, renameSync, rmdirSync,
  symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

function required(name) {
  assert.ok(process.env[name]?.trim(), `${name} is required`);
  return process.env[name];
}
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const binary = resolve(required('SKARBIEC'));
const state = resolve(required('SKARBIEC_ACQUISITION_FILE'));
const root = dirname(state);
assert.ok(root.startsWith(join(repo, 'target/real-tests/acquisition') + sep));
const consumer = required('SKARBIEC_TEST_CONSUMER');
const item = required('SKARBIEC_TEST_ITEM');
const field = required('SKARBIEC_TEST_FIELD');
const value = required('SKARBIEC_TEST_VALUE');
const tokenFile = resolve(required('SKARBIEC_TEST_TOKEN_FILE'));
assert.equal(dirname(tokenFile), root);
const token = readFileSync(tokenFile, 'utf8').trim();
const hash = createHash('sha256').update(token).digest('hex');
const original = readFileSync(state);
assert.ok(JSON.parse(original).tokens[hash], 'the real issued bearer must be persisted');
const report = { revision: required('SKARBIEC_TEST_SOURCE_REVISION'), binary,
  binarySha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
  commands: [], requests: [], serverOutput: [], passed: false };
const args = ['serve', '--port', required('SKARBIEC_TEST_HTTP_PORT')];
const child = spawn(binary, args, { cwd: repo, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
report.commands.push({ program: binary, args });
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
let displaced = false;
let directoryCreated = false;
let linkCreated = false;
const retained = join(root, 'acquisitions.retained.json');
try {
  const address = await ready;
  async function redeem(presented) {
    const response = await fetch(new URL('/v1/acquisitions/read', address), {
      method: 'POST', headers: { 'Content-Type': 'application/json',
        'X-Consumer': consumer, Authorization: `Bearer ${presented}` },
      body: JSON.stringify({ id: item, field }),
    });
    const text = await response.text();
    report.requests.push({ path: '/v1/acquisitions/read', status: response.status, text });
    return { status: response.status, body: JSON.parse(text) };
  }
  const refused = await redeem(randomUUID());
  assert.equal(refused.status, constants.HTTP_STATUS_UNAUTHORIZED);
  assert.deepEqual(readFileSync(state), original, 'unknown bearer must not spend the genuine bearer');
  renameSync(state, retained);
  displaced = true;
  mkdirSync(state);
  directoryCreated = true;
  const unavailable = await redeem(token);
  assert.equal(unavailable.status, constants.HTTP_STATUS_SERVICE_UNAVAILABLE);
  const prefix = 'the acquisition could not be redeemed: ';
  assert.ok(unavailable.body.error.startsWith(prefix));
  const cause = unavailable.body.error.slice(prefix.length);
  const cliArgs = ['acquisition', 'read', consumer, item, field, '--token-file', tokenFile];
  const cli = spawnSync(binary, cliArgs, { cwd: repo, env: process.env, encoding: 'utf8' });
  report.commands.push({ program: binary, args: cliArgs, status: cli.status,
    signal: cli.signal, stdout: cli.stdout, stderr: cli.stderr, error: cli.error?.message });
  assert.ifError(cli.error);
  assert.equal(cli.signal, null);
  assert.ok(cli.status !== null && cli.status);
  assert.ok(cause && cli.stderr.includes(cause), 'HTTP must retain the actual CLI storage refusal cause');
  assert.deepEqual(readFileSync(retained), original, 'storage refusal must preserve the original state');
  rmdirSync(state);
  directoryCreated = false;
  const missingTarget = join(root, randomUUID());
  symlinkSync(missingTarget, state);
  linkCreated = true;
  const linked = await redeem(token);
  assert.equal(linked.status, constants.HTTP_STATUS_SERVICE_UNAVAILABLE);
  assert.equal(linked.body.error, unavailable.body.error,
    'a dangling symlink must receive the actual non-regular-file refusal, not fresh empty state');
  assert.ok(lstatSync(state).isSymbolicLink());
  assert.equal(readlinkSync(state), missingTarget, 'refusal must not replace the dangling link');
  assert.deepEqual(readFileSync(retained), original, 'link refusal must preserve the genuine bearer');
  unlinkSync(state);
  linkCreated = false;
  renameSync(retained, state);
  displaced = false;
  const recovered = await redeem(token);
  assert.equal(recovered.status, constants.HTTP_STATUS_OK);
  assert.deepEqual(recovered.body, { consumer, item, field, value });
  assert.equal(Object.hasOwn(JSON.parse(readFileSync(state)).tokens, hash), false);
  const replay = await redeem(token);
  assert.equal(replay.status, constants.HTTP_STATUS_UNAUTHORIZED);
  report.passed = true;
} catch (error) {
  report.failure = error.stack ?? String(error);
  throw error;
} finally {
  try {
    if (directoryCreated) rmdirSync(state);
    if (linkCreated) unlinkSync(state);
    if (displaced) renameSync(retained, state);
  } catch (error) {
    report.cleanupFailure = error.stack ?? String(error);
    report.passed = false;
    throw error;
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
    writeFileSync(join(root, 'http-report.json'), JSON.stringify(report, null, '\t'));
  }
}
