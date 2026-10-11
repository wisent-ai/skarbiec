#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

function required(key) {
  assert.ok(process.env[key]?.trim(), `${key} is required`);
  return process.env[key];
}
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const binary = resolve(required('SKARBIEC'));
const revision = required('SKARBIEC_TEST_SOURCE_REVISION');
const fixture = resolve(required('SKARBIEC_TEST_VAULT_FILE'));
const original = readFileSync(fixture);
const vault = JSON.parse(original);
assert.ok(vault && typeof vault === 'object' && !Array.isArray(vault));
assert.equal(typeof vault.owner, 'string');
for (const field of ['items', 'recipients', 'tokens']) {
  assert.ok(vault[field] && typeof vault[field] === 'object' && !Array.isArray(vault[field]),
    `the genuine fixture must declare ${field}`);
}
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const runs = join(root, 'target/real-tests/vault-inventory');
mkdirSync(runs, { recursive: true });
const directory = mkdtempSync(join(runs, 'run-'));
const home = join(directory, 'home');
mkdirSync(home);
const env = { ...process.env, HOME: home };
delete env.SKARBIEC_VAULT_FILE;
const report = { revision, binary, binarySha256: hash(readFileSync(binary)),
  fixtureSha256: hash(original), testSha256: hash(readFileSync(fileURLToPath(import.meta.url))),
  commands: [], observations: [], passed: false };
function command(program, args) {
  const result = spawnSync(program, args, { cwd: root, env, encoding: 'utf8' });
  report.commands.push({ program, args, status: result.status, signal: result.signal,
    stdout: result.stdout, stderr: result.stderr, error: result.error?.message });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  assert.ok(result.status !== null && !result.status, result.stderr);
  return result.stdout;
}
function inventory() { return JSON.parse(command(binary, ['vaults'])); }
function filesystemCause(operation) {
  try { operation(); }
  catch (error) { assert.equal(typeof error.errno, 'number'); return Math.abs(error.errno); }
  assert.fail('the isolated filesystem operation must fail');
}
function unreadable(value, path, errno) {
  const entry = value.unreadable.find(entry => entry.path === path);
  assert.ok(entry, `the inventory must retain ${path}`);
  assert.ok(entry.cause.includes(`os error ${errno}`), entry.cause);
  report.observations.push(entry);
}
try {
  assert.equal(command('git', ['rev-parse', 'HEAD']).trim(), revision);
  assert.equal(command('git', ['status', '--porcelain', '--untracked-files=no']).trim(), '');
  assert.equal(JSON.parse(command(binary, ['version'])).commit, revision);
  const empty = inventory();
  assert.deepEqual(empty.vaults, []);
  assert.deepEqual(empty.unreadable, []);
  const candidate = join(home, 'retained.vault.json');
  copyFileSync(fixture, candidate);
  const readable = inventory();
  assert.deepEqual(readable.unreadable, []);
  assert.deepEqual(readable.vaults, [{ path: candidate, owner: vault.owner,
    items: Object.keys(vault.items).length, recipients: Object.keys(vault.recipients).length,
    tokens: Object.keys(vault.tokens).length }]);
  const dangling = join(home, 'dangling.vault.json');
  symlinkSync(join(home, 'absent-vault'), dangling);
  unreadable(inventory(), dangling, filesystemCause(() => statSync(dangling)));
  const stado = join(home, '.stado');
  writeFileSync(stado, original, { flag: 'wx' });
  unreadable(inventory(), stado, filesystemCause(() => readdirSync(stado)));
  const characters = Array.from(original.toString('utf8').trimEnd());
  assert.equal(characters.pop(), '}', 'genuine vault must end with an object delimiter');
  const damaged = characters.join('');
  writeFileSync(candidate, damaged);
  const invalid = inventory();
  assert.deepEqual(invalid.vaults, []);
  const parseError = invalid.unreadable.find(entry => entry.path === candidate);
  assert.ok(parseError?.cause.startsWith('is not valid JSON:'), JSON.stringify(invalid));
  assert.equal(readFileSync(candidate, 'utf8'), damaged);
  rmSync(dangling);
  rmSync(stado);
  writeFileSync(candidate, original);
  const recovered = inventory();
  assert.deepEqual(recovered.vaults, readable.vaults);
  assert.deepEqual(recovered.unreadable, []);
  assert.equal(hash(readFileSync(candidate)), hash(original));
  assert.equal(hash(readFileSync(fixture)), hash(original));
  report.passed = true;
} catch (error) {
  report.failure = error.stack;
  throw error;
} finally {
  try { rmSync(home, { recursive: true }); }
  finally { writeFileSync(join(directory, 'report.json'), `${JSON.stringify(report)}\n`); }
}
