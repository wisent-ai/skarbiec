#!/usr/bin/env node
// Real test that Skarbiec reaches Weles credential admission and the vault
// owner in process, through the built binary on a vault of its own (HOME,
// the vault, its journal and the Stado state all under this checkout's
// target directory) with a PATH that holds no program at all, so a bridge,
// node or stado it tried to start would fail the command it served.
//
// One loopback peer plays the three parties Skarbiec talks to: this host's
// Stado resolver API (`GET /v1/resolve/service/<service>` with
// X-Stado-Consumer, as `stado serve` answers it), Weles's credential
// admission (`POST /api/v1/credential-operations`), and the owner Skarbiec
// (`POST /v1/operator/status`). The binary under test must:
//   - refuse with WELES_ENDPOINT_UNRESOLVED, naming the state file and
//     `stado resolver status`, when no resolver has published its state, and
//     when the state names no api_bind;
//   - refuse with WELES_CREDENTIAL_BEARER_UNRESOLVED, naming the file and the
//     fix, when the bearer file is missing and when other accounts can read
//     it, sending nothing to Weles;
//   - send one v3 dry-run request with the bearer and read Weles's plan;
//   - carry Weles's own code and status when it refuses, and say
//     WELES_CREDENTIAL_TRANSPORT_FAILED when the connection drops;
//   - forward `status` to the owner the resolver names for the route's
//     consumer, and refuse a consumer the resolver does not admit, naming
//     the `stado service directory consumer add` that declares it.
// Every command, request and answer goes to the run's report.json.
//
// Usage: SKARBIEC=<binary under test> node tests/credential/admission_in_process.mjs
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
assert.ok(process.env.SKARBIEC?.trim(), 'set SKARBIEC to the skarbiec binary under test');
const binary = resolve(process.env.SKARBIEC);
const revision = process.env.SKARBIEC_TEST_SOURCE_REVISION
  ?? spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).stdout.trim();
const base = join(repo, 'target/real-tests/credential');
mkdirSync(base, { recursive: true });
const root = mkdtempSync(join(base, 'admission-'));
chmodSync(root, 0o700);
const home = join(root, 'home');
const emptyPath = join(root, 'empty-path');
mkdirSync(join(home, '.stado'), { recursive: true });
mkdirSync(emptyPath);
const report = {
  revision, binary,
  binarySha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
  commands: [], peer: [], checks: [], passed: false,
};

// What the peer answers Weles with next: plan, refuse or drop.
let welesMode = 'plan';
const ADMITTED = { 'weles-admission': 'skarbiec-weles-credential-client', skarbiec: 'operator' };
const peer = createServer((request, response) => {
  const chunks = [];
  request.on('data', chunk => chunks.push(chunk));
  request.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    const seen = { method: request.method, url: request.url, headers: request.headers, body };
    report.peer.push(seen);
    const answer = (status, value) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(value));
    };
    const resolveMatch = request.url.match(/^\/v1\/resolve\/service\/([^/?]+)$/);
    if (request.method === 'GET' && resolveMatch) {
      const service = resolveMatch[1];
      const consumer = request.headers['x-stado-consumer'];
      if (ADMITTED[service] !== consumer) {
        return answer(503, { error: `consumer "${consumer}" is not authorized for service "${service}"` });
      }
      return answer(200, { service: `stado://service/${service}`, generation: 1,
        gateway_url: `http://127.0.0.1:${peer.address().port}`, capabilities: [] });
    }
    if (request.method === 'POST' && request.url === '/api/v1/credential-operations') {
      const sent = JSON.parse(body);
      if (welesMode === 'drop') return request.socket.destroy();
      if (welesMode === 'refuse') {
        return answer(403, { code: 'WELES_CREDENTIAL_SCOPE_REFUSED',
          message: 'the caller lacks call:weles#credential-operations', providerEffect: 'none' });
      }
      return answer(200, { version: sent.version, status: 'operation_plan', operation: sent.operation,
        provider: sent.provider, vaultItemId: sent.credential_id, message: 'would acquire' });
    }
    if (request.method === 'POST' && request.url === '/v1/operator/status') {
      return answer(200, { ok: true, owner: 'the peer standing in for the owner' });
    }
    return answer(404, { error: 'not_found' });
  });
});
await new Promise(done => peer.listen(0, '127.0.0.1', done));
const port = peer.address().port;

const stateFile = join(home, '.stado', 'resolver-state.json');
const bearerFile = join(home, '.stado', 'skarbiec-weles-credential-client-token');
const env = {
  HOME: home, PATH: emptyPath,
  SKARBIEC_VAULT_FILE: join(root, 'vault.json'),
  SKARBIEC_AUDIT_FILE: join(root, 'audit.jsonl'),
};
async function run(args, extra = {}) {
  const environment = { ...env, ...extra };
  for (const [name, value] of Object.entries(environment)) if (value === undefined) delete environment[name];
  // The peer answers on this event loop, so the binary runs without blocking it.
  const { spawn } = await import('node:child_process');
  const child = spawn(binary, args, { env: environment, cwd: root });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const status = await new Promise(done => child.on('close', done));
  report.commands.push({ args, env: extra, status, stdout, stderr });
  return { status, stdout, stderr, text: `${stdout}\n${stderr}` };
}
function check(condition, what, detail) {
  report.checks.push({ what, ok: Boolean(condition) });
  assert.ok(condition, `${what}: ${detail}`);
}
const welesRequests = () => report.peer.filter(seen => seen.url === '/api/v1/credential-operations').length;
const acquire = ['credential', 'acquire', '--local', '--provider', 'admission-probe',
  '--consumer', 'admission-probe-writer', '--signup-origin', 'https://example.com', '--dry-run'];

try {
  const init = await run(['init', 'admission-owner']);
  check(init.status === 0, 'init succeeds with an empty PATH', init.stderr);

  let answer = await run(acquire);
  check(answer.text.includes('WELES_ENDPOINT_UNRESOLVED') && answer.text.includes(stateFile)
    && answer.text.includes('stado resolver status'),
  'no resolver state is WELES_ENDPOINT_UNRESOLVED naming the file and the remedy', answer.text);

  writeFileSync(stateFile, JSON.stringify({ pid: 1, state: 'serving' }));
  answer = await run(acquire);
  check(answer.text.includes('WELES_ENDPOINT_UNRESOLVED') && answer.text.includes('names no api_bind'),
    'a state without api_bind is WELES_ENDPOINT_UNRESOLVED saying so', answer.text);

  writeFileSync(stateFile, JSON.stringify({ pid: 1, state: 'serving', api_bind: `127.0.0.1:${port}` }));
  answer = await run(acquire);
  check(answer.text.includes('WELES_CREDENTIAL_BEARER_UNRESOLVED') && answer.text.includes(bearerFile),
    'a missing bearer file is WELES_CREDENTIAL_BEARER_UNRESOLVED naming it', answer.text);
  writeFileSync(bearerFile, 'admission-bearer-1234\n', { mode: 0o644 });
  chmodSync(bearerFile, 0o644);
  answer = await run(acquire);
  check(answer.text.includes('WELES_CREDENTIAL_BEARER_UNRESOLVED') && answer.text.includes('chmod 600'),
    'a bearer file others can read is refused naming chmod 600', answer.text);
  check(welesRequests() === 0, 'nothing is sent to Weles before the bearer is readable', welesRequests());

  chmodSync(bearerFile, 0o600);
  answer = await run(acquire);
  const sent = report.peer.filter(seen => seen.url === '/api/v1/credential-operations').at(-1);
  check(sent && sent.headers.authorization === 'Bearer admission-bearer-1234',
    'Weles receives the bearer from the owner-only file', JSON.stringify(sent?.headers));
  const wire = JSON.parse(sent.body);
  check(wire.version === 'skarbiec.credential-operation.v3' && wire.mode === 'submit'
    && wire.dry_run === true && wire.provider === 'admission-probe',
  'Weles receives one v3 dry-run submit for the provider', sent.body);
  const planned = JSON.parse(answer.stdout);
  check(answer.status === 0 && planned.ok === true && planned.weles.status === 'operation_plan',
    'the dry run reads Weles plan', answer.text);

  welesMode = 'refuse';
  answer = await run(acquire);
  check(answer.text.includes('WELES_CREDENTIAL_SCOPE_REFUSED') && answer.text.includes('403'),
    'a Weles refusal keeps its own code and status', answer.text);
  welesMode = 'drop';
  answer = await run(acquire);
  check(answer.text.includes('WELES_CREDENTIAL_TRANSPORT_FAILED'),
    'a dropped connection is WELES_CREDENTIAL_TRANSPORT_FAILED', answer.text);

  const config = join(root, 'stado.config.json');
  writeFileSync(config, JSON.stringify({ secrets: { skarbiec: { url: 'stado://service/skarbiec?consumer=operator' } } }));
  answer = await run(['status'], { SKARBIEC_VAULT_FILE: undefined, STADO_CONFIG: config });
  const forwarded = report.peer.filter(seen => seen.url === '/v1/operator/status').at(-1);
  check(answer.status === 0 && forwarded && JSON.parse(forwarded.body).forwardedToOwner === true
    && JSON.parse(answer.stdout).source?.endpoint === `http://127.0.0.1:${port}`,
  'status is forwarded to the owner the resolver names', answer.text);

  writeFileSync(config, JSON.stringify({ secrets: { skarbiec: { url: 'stado://service/skarbiec?consumer=stranger' } } }));
  answer = await run(['status'], { SKARBIEC_VAULT_FILE: undefined, STADO_CONFIG: config });
  check(answer.status !== 0 && answer.text.includes('not authorized')
    && answer.text.includes('stado service directory consumer add skarbiec stranger'),
  'a consumer the resolver does not admit is refused naming how to declare it', answer.text);

  report.passed = true;
} finally {
  peer.close();
  writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, '\t'));
  console.log(`${report.passed ? 'PASS' : 'FAIL'}: ${join(root, 'report.json')}`);
}
