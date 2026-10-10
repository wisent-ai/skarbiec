#!/usr/bin/env node
// Real fleet vault journey. Requires an installed candidate and the actual
// non-owner Stado declaration; never starts a substitute vault or server.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
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
const configPath = resolve(required('SKARBIEC_TEST_STADO_CONFIG'));
const config = JSON.parse(readFileSync(configPath, 'utf8'));
assert.ok(config.secrets?.skarbiec?.url, 'a real owner route is required');
assert.ok(!config.secrets.skarbiec.vault_file, 'this journey must run on a non-owner host');
const home = required('HOME');
const copy = join(home, '.local/share/skarbiec/skarbiec.vault.json');
const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const originalCopy = existsSync(copy) ? hash(copy) : null;
const runs = join(root, 'target/real-tests/remote-owner');
mkdirSync(runs, { recursive: true });
const directory = mkdtempSync(join(runs, 'run-'));
const id = `remote-owner-test-${randomUUID()}`;
const role = `remote-owner-test-${randomUUID()}`;
const password = randomUUID();
const replacement = randomUUID();
const payload = { schema: 'skarbiec.item.v2', kind: 'login', fields: { username: id, password }, context: {} };
const report = { revision, binary, binarySha256: hash(binary), testSha256: hash(fileURLToPath(import.meta.url)),
  commands: [], observations: [], item: id, passed: false };
const env = { ...process.env, STADO_CONFIG: configPath };
delete env.SKARBIEC_VAULT_FILE;
let endpoint;
let mayExist = false;
function invoke(program, args, input) {
  const result = spawnSync(program, args, { cwd: root, env, input, encoding: 'utf8' });
  report.commands.push({ program, args, status: result.status, signal: result.signal,
    stdout: result.stdout, stderr: result.stderr, error: result.error?.message });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return result;
}
function success(program, args, input) {
  const result = invoke(program, args, input);
  assert.ok(result.status !== null && !result.status, result.stderr);
  return result.stdout;
}
function cli(args, input) { return success(binary, args, input); }
async function operator(path, body) {
  const response = await fetch(`${endpoint}${path}`, { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const text = await response.text();
  report.observations.push({ path, status: response.status, body: text });
  assert.ok(response.ok, `${path}: ${text}`);
  return JSON.parse(text);
}
try {
  assert.equal(success('git', ['rev-parse', 'HEAD']).trim(), revision);
  assert.equal(success('git', ['status', '--porcelain', '--untracked-files=no']).trim(), '', 'candidate must be committed');
  const status = JSON.parse(cli(['status']));
  assert.equal(status.source.kind, 'remote');
  assert.equal(status.source.route, config.secrets.skarbiec.url);
  assert.ok(status.vault, 'status must identify the serving vault');
  endpoint = status.source.endpoint;
  report.owner = status;
  const tags = [`stado:role:${role}`, id];
  mayExist = true;
  const write = JSON.parse(cli(['set-json', id, '--type', 'login', '--tags', tags.join(',')], JSON.stringify(payload)));
  assert.equal(write.id, id);
  assert.equal(write.created, true);
  assert.deepEqual(JSON.parse(cli(['get', id])), payload);
  assert.equal(cli(['get', id, '--field', 'password']), `${password}\n`);
  assert.equal(cli(['get', `role:${role}`, '--field', 'password']), `${password}\n`);
  const before = JSON.parse(cli(['get', id, '--revision']));
  assert.equal(before.item, id);
  payload.fields.password = replacement;
  cli(['set-json', id], JSON.stringify(payload));
  const after = JSON.parse(cli(['get', id, '--revision']));
  assert.equal(after.item_uid, before.item_uid);
  assert.ok(after.revision > before.revision, 'owner revision must advance after the write');
  const stored = JSON.parse(cli(['list'])).find(item => item.id === id);
  assert.deepEqual(new Set(stored.tags), new Set(tags), 'an unqualified update must preserve metadata');
  assert.equal(cli(['get', id, '--field', 'password']), `${replacement}\n`);
  payload.fields.password = password;
  assert.equal(JSON.parse(cli(['set-json', id, '--if-absent'], JSON.stringify(payload))).created, false);
  assert.equal(cli(['get', id, '--field', 'password']), `${replacement}\n`);
  const missing = invoke(binary, ['get', id, '--field', 'absent-test-field']);
  assert.ok(missing.status !== null && missing.status);
  assert.ok(missing.stderr.includes('absent-test-field'));
  const invalid = invoke(binary, ['set-json', id], '{');
  assert.ok(invalid.status !== null && invalid.status);
  assert.equal(cli(['get', id, '--field', 'password']), `${replacement}\n`);
  const graphical = await operator('/v1/operator/credential', { operation: 'get', item: id, field: 'password' });
  assert.equal(graphical.value, replacement, 'graphical API and CLI must observe the same owner value');
  await operator('/v1/operator/items/purge', { id });
  mayExist = false;
  assert.ok(!JSON.parse(cli(['list', '--all'])).some(item => item.id === id));
  const absent = invoke(binary, ['get', id]);
  assert.ok(absent.status !== null && absent.status, 'a purged test item must remain absent');
  assert.equal(existsSync(copy) ? hash(copy) : null, originalCopy, 'the client copy must remain untouched');
  report.passed = true;
} catch (error) {
  report.error = error.stack;
  throw error;
} finally {
  let cleanupFailure;
  try {
    if (mayExist) {
      const remaining = await operator('/v1/operator/items/list', { flags: { all: 'true' }, positionals: [] });
      if (remaining.some(item => item.id === id)) await operator('/v1/operator/items/purge', { id });
      const afterCleanup = await operator('/v1/operator/items/list', { flags: { all: 'true' }, positionals: [] });
      assert.ok(!afterCleanup.some(item => item.id === id), 'cleanup must remove a write whose acknowledgement was lost');
    }
  } catch (error) {
    report.passed = false;
    report.cleanupError = error.stack;
    cleanupFailure = error;
  }
  writeFileSync(join(directory, 'report.json'), JSON.stringify(report));
  console.log(`Retained fleet-vault evidence: ${directory}`);
  if (cleanupFailure) throw cleanupFailure;
}
