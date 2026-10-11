#!/usr/bin/env node
// Real owner-vault CLI/operator journey. Creates only a unique isolated item.
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function required(name) {
  assert.ok(process.env[name]?.trim(), `${name} is required`);
  return process.env[name].trim();
}
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const binary = resolve(required('SKARBIEC'));
const revision = required('SKARBIEC_TEST_SOURCE_REVISION');
const endpoint = required('SKARBIEC_TEST_OPERATOR_ENDPOINT');
const directoryRoot = join(root, 'target/real-tests/conditional-payload');
mkdirSync(directoryRoot, { recursive: true });
const directory = mkdtempSync(join(directoryRoot, 'run-'));
const id = `conditional-payload-${randomUUID()}`;
const original = { schema: 'skarbiec.item.v2', kind: 'login',
  fields: { username: `${id}@example.invalid`, password: randomUUID() }, context: {} };
const updated = { ...original, fields: { ...original.fields, password: randomUUID() } };
const rebound = { ...updated, fields: { ...updated.fields, username: `${randomUUID()}@example.invalid` } };
const report = { revision, binary, item: id, endpoint, passed: false, commands: [], requests: [],
  binarySha256: createHash('sha256').update(readFileSync(binary)).digest('hex') };
let created = false;
function save() { writeFileSync(join(directory, 'report.json'), JSON.stringify(report, null, '\t')); }
function run(program, args, input) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', input });
  report.commands.push({ program, args, status: result.status, signal: result.signal,
    stdout: result.stdout, stderr: result.stderr, error: result.error?.message });
  save();
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return result;
}
function success(args, payload) {
  const result = run(binary, args, payload === undefined ? undefined : JSON.stringify(payload));
  assert.ok(result.status !== null && !result.status, result.stderr);
  return JSON.parse(result.stdout);
}
function refused(args, payload, cause) {
  const result = run(binary, args, JSON.stringify(payload));
  assert.ok(result.status, 'command must refuse');
  assert.ok(result.stderr.includes(cause), result.stderr);
}
async function operator(expected, payload, accepted) {
  const response = await fetch(`${endpoint}/v1/operator/credential`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ operation: 'set-json', item: id, 'if-unchanged': true,
      payload: { expected, payload } }),
  });
  const body = await response.text();
  report.requests.push({ operation: 'set-json', status: response.status, body });
  save();
  assert.equal(response.ok, accepted, body);
  if (!accepted) assert.ok(body.includes('item_payload_changed'), body);
}
try {
  const head = run('git', ['rev-parse', 'HEAD']);
  assert.ok(head.status !== null && !head.status, head.stderr);
  assert.equal(head.stdout.trim(), revision);
  assert.equal(success(['version']).commit, revision);
  const createdResult = success(['set-json', id, '--if-absent'], original);
  assert.equal(createdResult.created, true);
  created = true;
  assert.deepEqual(success(['get', id]), original);
  success(['set-json', id, '--if-unchanged'], { expected: original, payload: updated });
  assert.deepEqual(success(['get', id]), updated);
  refused(['set-json', id, '--if-unchanged'], { expected: original, payload: rebound }, 'item_payload_changed');
  assert.deepEqual(success(['get', id]), updated);
  refused(['set-json', id, '--if-absent', '--if-unchanged'], { expected: updated, payload: rebound }, 'only one');
  refused(['set-json', id, '--if-unchanged'], { expected: updated }, 'requires expected and payload');
  assert.deepEqual(success(['get', id]), updated);
  await operator(updated, rebound, true);
  assert.deepEqual(success(['get', id]), rebound);
  await operator(updated, original, false);
  assert.deepEqual(success(['get', id]), rebound);
  success(['purge', id, '--yes']);
  created = false;
  assert.ok(!success(['list', '--all']).some(item => item.id === id));
  report.passed = true;
} catch (error) {
  report.error = error.stack;
  throw error;
} finally {
  if (created) {
    try { success(['purge', id, '--yes']); }
    catch (error) { report.cleanupError = error.message; report.passed = false; }
  }
  save();
  console.log(directory);
  if (report.cleanupError) throw new Error(report.cleanupError);
}
