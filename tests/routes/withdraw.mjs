#!/usr/bin/env node
// Real candidate CLI and persisted route table; no substitute service or provider.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
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
const base = join(root, 'target/real-tests/route-withdraw');
mkdirSync(base, { recursive: true });
const directory = mkdtempSync(join(base, 'run-'));
const table = join(directory, 'routes.json');
const audit = join(directory, 'audit.jsonl');
const env = { ...process.env, SKARBIEC_VAULT_FILE: join(directory, 'absent.vault.json'),
  SKARBIEC_CAPABILITY_ROUTES_FILE: table, SKARBIEC_AUDIT_FILE: audit };
const resource = `form:${randomUUID()}`;
const tag = `stado:role:route-test-${randomUUID()}`;
const otherResource = `form:${randomUUID()}`;
const otherTag = `stado:role:route-test-${randomUUID()}`;
const reason = `withdrawal journey ${randomUUID()}`;
const declarationReason = `declaration journey ${randomUUID()}`;
const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const report = { revision, binary, binarySha256: hash(binary), commands: [], passed: false };
function invoke(program, args) {
  const result = spawnSync(program, args, { cwd: root, env, encoding: 'utf8' });
  report.commands.push({ program, args, status: result.status, signal: result.signal,
    stdout: result.stdout, stderr: result.stderr, error: result.error?.message });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return result;
}
function success(program, args) {
  const result = invoke(program, args);
  assert.ok(result.status !== null && !result.status, result.stderr);
  return result.stdout;
}
function cli(args) { return JSON.parse(success(binary, args)); }
try {
  assert.equal(success('git', ['rev-parse', 'HEAD']).trim(), revision);
  success('git', ['diff', '--quiet']);
  success('git', ['diff', '--cached', '--quiet']);
  // Declarations are allowed ahead of credential provisioning by the product contract.
  const declared = cli(['route', 'declare', '--resource', resource, '--tag', tag,
    '--field', 'password', '--reason', declarationReason]);
  assert.equal(declared.declared, true);
  const independent = cli(['route', 'declare', '--resource', otherResource, '--tag', otherTag,
    '--field', 'password', '--reason', declarationReason]);
  assert.equal(independent.declared, true);
  const original = readFileSync(table, 'utf8');
  assert.equal(JSON.parse(original)[resource].tag, tag);
  assert.equal(JSON.parse(original)[otherResource].tag, otherTag);
  const refused = invoke(binary, ['route', 'withdraw', '--resource', resource]);
  assert.ok(refused.status !== null && refused.status);
  assert.ok(refused.stderr.includes('--reason'));
  assert.equal(readFileSync(table, 'utf8'), original, 'refusal must preserve the declaration');
  const withdrawn = cli(['route', 'withdraw', '--resource', resource, '--reason', reason]);
  assert.equal(withdrawn.withdrawn, true);
  assert.equal(withdrawn.resource, resource);
  assert.equal(readFileSync(withdrawn.backup, 'utf8'), original, 'backup must retain the prior table');
  const expected = JSON.parse(original);
  delete expected[resource];
  assert.deepEqual(JSON.parse(readFileSync(table, 'utf8')), expected,
    'withdrawal must remove only its selected declaration and preserve unrelated routes');
  const after = hash(table);
  const journal = readFileSync(audit, 'utf8');
  const withdrawalEntry = journal.split('\n').filter(Boolean).map(JSON.parse)
    .find(entry => entry.op === 'capability-route-withdrawn' && entry.extra.resource === resource);
  assert.ok(withdrawalEntry, 'the hash-chained journal must identify this withdrawal');
  assert.equal(withdrawalEntry.extra.reason, reason);
  assert.deepEqual(withdrawalEntry.extra.row, JSON.parse(original)[resource]);
  assert.equal(withdrawalEntry.extra.backup, withdrawn.backup);
  const absent = cli(['route', 'withdraw', '--resource', resource, '--reason', reason]);
  assert.equal(absent.withdrawn, false);
  assert.equal(absent.backup, null);
  assert.equal(hash(table), after, 'repeated withdrawal must not rewrite the table');
  assert.equal(readFileSync(audit, 'utf8'), journal, 'repeated withdrawal must not append a mutation');
  report.passed = true;
} catch (error) {
  report.error = error.stack;
  throw error;
} finally {
  writeFileSync(join(directory, 'report.json'), JSON.stringify(report));
  console.log(`Retained route withdrawal evidence: ${directory}`);
}
