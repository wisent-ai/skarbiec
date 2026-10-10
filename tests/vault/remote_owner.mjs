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
const recoveryCode = randomUUID();
const payload = { schema: 'skarbiec.item.v2', kind: 'login',
  fields: { username: id, password, recovery_codes: [recoveryCode] }, context: {} };
const report = { revision, binary, binarySha256: hash(binary), testSha256: hash(fileURLToPath(import.meta.url)),
  commands: [], observations: [], item: id, passed: false };
const env = { ...process.env, STADO_CONFIG: configPath };
delete env.SKARBIEC_VAULT_FILE;
let endpoint;
let mayExist = false;
function invoke(program, args, input, commandEnv = env) {
  const result = spawnSync(program, args, { cwd: root, env: commandEnv, input, encoding: 'utf8' });
  report.commands.push({ program, args, status: result.status, signal: result.signal,
    configuration: commandEnv.STADO_CONFIG,
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
async function operator(path, body, expectedSuccess = true) {
  const response = await fetch(`${endpoint}${path}`, { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const text = await response.text();
  report.observations.push({ path, status: response.status, body: text });
  assert.equal(response.ok, expectedSuccess, `${path}: ${text}`);
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
  assert.ok(missing.stderr.includes(status.vault), 'a missing field must identify the serving vault');
  assert.ok(missing.stderr.includes('username') && missing.stderr.includes('password'),
    'a missing field must identify the available fields without exposing their values');
  assert.ok(!missing.stderr.includes(replacement), 'refusal diagnostics must not reveal the secret');
  const nonText = invoke(binary, ['get', id, '--field', 'recovery_codes']);
  assert.ok(nonText.status !== null && nonText.status);
  assert.equal(nonText.stdout, '', 'a refused field must not emit a partial value');
  assert.ok(nonText.stderr.includes(status.vault) && nonText.stderr.includes('recovery_codes'));
  assert.ok(nonText.stderr.includes('a list'), 'a non-text field must identify its actual type');
  assert.ok(!nonText.stderr.includes(recoveryCode), 'a type diagnostic must not print array contents');
  const graphicalRefusal = await operator('/v1/operator/credential',
    { operation: 'get', item: id, field: 'recovery_codes' }, false);
  assert.ok(graphicalRefusal.error.includes(status.vault));
  assert.ok(graphicalRefusal.error.includes('recovery_codes') && graphicalRefusal.error.includes('a list'));
  assert.ok(!graphicalRefusal.error.includes(recoveryCode));
  assert.deepEqual(JSON.parse(cli(['get', id])).fields.recovery_codes, [recoveryCode],
    'refused text projection must preserve the canonical typed value');
  const unbound = invoke(binary, ['get', `role:${randomUUID()}`]);
  assert.ok(unbound.status !== null && unbound.status);
  assert.ok(unbound.stderr.includes(status.vault), 'role resolution failure must identify the serving vault');
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
  assert.ok(absent.stderr.includes(status.vault), 'a missing item must identify the serving vault');
  const invalidConfig = join(directory, 'invalid-stado.json');
  writeFileSync(invalidConfig, '{');
  const unreadableRoute = invoke(binary, ['status'], undefined, { ...env, STADO_CONFIG: invalidConfig });
  assert.ok(unreadableRoute.status !== null && unreadableRoute.status,
    'a malformed explicit owner declaration must refuse, not select the client copy');
  assert.ok(unreadableRoute.stderr.includes(invalidConfig),
    'the routing refusal must name the actual malformed declaration');
  assert.equal(unreadableRoute.stdout.trim(), '', 'a refused route must not publish vault status');
  for (const [declaration, field] of [
    [[], 'vault routing declaration'],
    [{ secrets: [] }, 'secrets'],
    [{ secrets: { skarbiec: [] } }, 'secrets.skarbiec'],
    [{ secrets: { skarbiec: { vault_file: [], url: config.secrets.skarbiec.url } } }, 'secrets.skarbiec.vault_file'],
    [{ secrets: { skarbiec: { vault_file: ' ', url: config.secrets.skarbiec.url } } }, 'secrets.skarbiec.vault_file'],
    [{ secrets: { skarbiec: { url: [] } } }, 'secrets.skarbiec.url'],
  ]) {
    writeFileSync(invalidConfig, JSON.stringify(declaration));
    const malformed = invoke(binary, ['status'], undefined, { ...env, STADO_CONFIG: invalidConfig });
    assert.ok(malformed.status !== null && malformed.status,
      `invalid ${field} must refuse instead of choosing another vault`);
    assert.ok(malformed.stderr.includes(invalidConfig) && malformed.stderr.includes(field),
      `routing refusal must identify the declaration and malformed ${field}`);
    assert.equal(malformed.stdout.trim(), '', 'an invalid declaration must not publish vault status');
  }
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
