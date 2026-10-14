#!/usr/bin/env node
// Real owner-vault CLI journey for the one restore verb: `restore <id>`
// brings a trashed item back, `restore <id> --at <at>` makes an earlier
// revision current again, and the former second spelling `restore-version`
// is refused as an unknown command. Creates only a unique isolated item and
// purges it at the end.
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
const directoryRoot = join(root, 'target/real-tests/restore');
mkdirSync(directoryRoot, { recursive: true });
const directory = mkdtempSync(join(directoryRoot, 'run-'));
const id = `restore-${randomUUID()}`;
const original = { schema: 'skarbiec.item.v2', kind: 'login',
  fields: { username: `${id}@example.invalid`, password: randomUUID() }, context: {} };
const updated = { ...original, fields: { ...original.fields, password: randomUUID() } };
const report = { revision, binary, item: id, passed: false, commands: [],
  binarySha256: createHash('sha256').update(readFileSync(binary)).digest('hex') };
let created = false;
function save() { writeFileSync(join(directory, 'report.json'), JSON.stringify(report, null, '\t')); }
function run(args, payload) {
  const input = payload === undefined ? undefined : JSON.stringify(payload);
  const result = spawnSync(binary, args, { cwd: root, encoding: 'utf8', input });
  report.commands.push({ args, status: result.status, signal: result.signal,
    stdout: result.stdout, stderr: result.stderr, error: result.error?.message });
  save();
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return result;
}
function success(args, payload) {
  const result = run(args, payload);
  assert.ok(result.status !== null && !result.status, result.stderr);
  return JSON.parse(result.stdout);
}
// Every revision this item's envelope records, read from the vault document
// `status` names; the envelope is cleartext, only payloads are encrypted.
function history() {
  const vault = JSON.parse(readFileSync(success(['status']).vault, 'utf8'));
  return vault.items[id].history.map(version => version.created_at);
}
try {
  const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' });
  assert.equal(head.stdout.trim(), revision);
  assert.equal(success(['version']).commit, revision);

  // The status a usage refusal exits with, measured on a word that is not a command.
  const unknown = run(['no-such-command']);
  assert.ok(unknown.status, 'an unknown command was accepted');
  const removed = run(['restore-version', id, 'now']);
  assert.equal(removed.status, unknown.status, removed.stderr);
  assert.ok(removed.stderr.includes('unknown command'), removed.stderr);
  const bare = run(['restore']);
  assert.equal(bare.status, unknown.status, bare.stderr);
  assert.ok(bare.stderr.includes('usage: restore <id> [--at <at>]'), bare.stderr);

  assert.equal(success(['set-json', id, '--if-absent'], original).created, true);
  created = true;
  success(['set-json', id, '--if-unchanged'], { expected: original, payload: updated });
  assert.deepEqual(success(['get', id]), updated);
  const [first] = history();
  assert.ok(first, 'the replaced revision was not kept in the item history');
  report.restoredAt = first;

  const missing = run(['restore', id, '--at', 'not-a-recorded-time']);
  assert.ok(missing.status, 'a time no revision was recorded at was accepted');
  assert.ok(missing.stderr.includes(`no version at not-a-recorded-time for ${id}`), missing.stderr);
  assert.deepEqual(success(['get', id]), updated);

  success(['restore', id, '--at', first]);
  assert.deepEqual(success(['get', id]), original);

  success(['delete', id]);
  assert.ok(run(['get', id]).status, 'a trashed item was read');
  success(['restore', id]);
  assert.deepEqual(success(['get', id]), original);

  success(['purge', id, '--yes']);
  created = false;
  assert.ok(!success(['list', '--all']).some(item => item.id === id));
  report.passed = true;
} catch (error) {
  report.error = error.stack;
  throw error;
} finally {
  if (created) {
    try {
      run(['delete', id]);
      success(['purge', id, '--yes']);
    } catch (error) { report.cleanupError = error.message; report.passed = false; }
  }
  save();
  console.log(directory);
  if (report.cleanupError) throw new Error(report.cleanupError);
}
