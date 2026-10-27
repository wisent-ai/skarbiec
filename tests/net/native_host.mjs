#!/usr/bin/env node
// Real browser host journey against an isolated Skarbiec vault and its
// loopback API. HOME, GNUPGHOME and the vault point into this checkout's
// target directory, so the operator's vault, keyring, grant and browser
// manifests are never read or written. The host is spoken to as a browser
// speaks to it: a native-messaging frame is the message's byte length as a
// 32-bit little-endian integer followed by that many bytes of JSON
// (https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-protocol).
//
// It checks that a login whose second factor is unusable fills with the
// reason (totp_unavailable naming totp seed) instead of no factor; that
// a field the grant does not cover is refused with the API's own words; that
// a frame without an action or a fill without an id says which is missing;
// that a frame cut short is refused with the bytes that arrived; and that a
// fill against a loopback API that is gone answers its failure.
//
// Supply SKARBIEC, SKARBIEC_TEST_SOURCE_REVISION, SKARBIEC_TEST_BINARY_SHA256
// and a free SKARBIEC_TEST_HTTP_PORT, then run node tests/net/native_host.mjs.
// The report's `qualified` is true only for a clean tree that tracks this file.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { constants as fsConstants, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function required(name) {
  assert.ok(process.env[name]?.trim(), `${name} is required`);
  return process.env[name];
}
function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const binary = resolve(required('SKARBIEC'));
const revision = required('SKARBIEC_TEST_SOURCE_REVISION');
const binarySha256 = digest(readFileSync(binary));
assert.equal(binarySha256, required('SKARBIEC_TEST_BINARY_SHA256'));
const source = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' });
assert.equal(source.status, 0, source.stderr);
assert.equal(source.stdout.trim(), revision);
// A run from a tree whose tracked files or this journey are not committed is
// still carried out and reported, but marked unqualified: its report names a
// source no revision holds.
const tracked = spawnSync('git', ['ls-files', '--error-unmatch', 'tests/net/native_host.mjs'],
  { cwd: repo, encoding: 'utf8' });
const clean = spawnSync('git', ['diff', '--quiet', 'HEAD'], { cwd: repo, encoding: 'utf8' });
const qualified = tracked.status === source.status && clean.status === source.status;

const base = join(repo, 'target/real-tests/net');
mkdirSync(base, { recursive: true });
const root = mkdtempSync(join(base, 'native-host-'));
const home = join(root, 'home');
// The keyring sits directly under target/: gpg-agent's socket lives in it,
// and a socket path under the run directory is longer than the system allows.
const keyring = join(repo, 'target', `g${process.pid}`);
mkdirSync(home, { mode: fsConstants.S_IRWXU });
mkdirSync(keyring, { mode: fsConstants.S_IRWXU });
const vault = join(root, 'vault.json');
const env = { ...process.env, HOME: home, GNUPGHOME: keyring, SKARBIEC_VAULT_FILE: vault,
  SKARBIEC_AUDIT_FILE: join(root, 'audit.jsonl'), SKARBIEC_CAPABILITY_FILE: join(root, 'capabilities.json'),
  SKARBIEC_CAPABILITY_ROUTES_FILE: join(root, 'capability-routes.json') };
const report = { revision, qualified, binary, binarySha256,
  testSha256: digest(readFileSync(fileURLToPath(import.meta.url))),
  commands: [], frames: [], serverOutput: [], passed: false };

function cli(args, input) {
  const run = spawnSync(binary, args, { cwd: repo, env, input, encoding: 'utf8' });
  report.commands.push({ program: binary, args, status: run.status, signal: run.signal,
    stderr: run.stderr, error: run.error?.message });
  assert.ifError(run.error);
  assert.equal(run.status, source.status, `skarbiec ${args.join(' ')}: ${run.stderr}`);
  return run.stdout;
}
function frame(value) {
  const body = Buffer.from(JSON.stringify(value));
  const length = Buffer.alloc(Uint32Array.BYTES_PER_ELEMENT);
  length.writeUInt32LE(body.length);
  return Buffer.concat([length, body]);
}
function frames(bytes) {
  const replies = [];
  let rest = bytes;
  while (rest.length) {
    const length = rest.readUInt32LE();
    const body = rest.subarray(Uint32Array.BYTES_PER_ELEMENT, Uint32Array.BYTES_PER_ELEMENT + length);
    replies.push(JSON.parse(body.toString('utf8')));
    rest = rest.subarray(Uint32Array.BYTES_PER_ELEMENT + length);
  }
  return replies;
}
// One browser host process: the frames written to its standard input in turn,
// then end of input; its replies, exit and standard error are kept.
function host(label, input) {
  const run = spawnSync(binary, ['browser', 'host'], { cwd: repo, env, input });
  const replies = run.status === source.status ? frames(run.stdout) : [];
  const record = { label, status: run.status, signal: run.signal, replies,
    stderr: run.stderr.toString('utf8'), error: run.error?.message };
  report.frames.push(record);
  assert.ifError(run.error);
  return record;
}

let child;
let closed;
try {
  cli(['init', `native-host-owner-${randomUUID()}`]);
  const domain = `native-host-${randomUUID()}.test`;
  const login = `native-host-login-${randomUUID()}`;
  cli(['set', login, '--type', 'login'], JSON.stringify({ schema: 'skarbiec.item.v2', kind: 'login',
    fields: { username: `user-${randomUUID()}`, password: `secret-${randomUUID()}`,
      totp_secret: 'not a base32 seed!' },
    context: { name: login, domains: [domain] } }));
  const port = required('SKARBIEC_TEST_HTTP_PORT');
  child = spawn(binary, ['serve', '--port', port], { cwd: repo, env, stdio: ['ignore', 'pipe', 'pipe'] });
  report.commands.push({ program: binary, args: ['serve', '--port', port] });
  closed = new Promise(done => child.once('close', (status, signal) => {
    report.serverExit = { status, signal };
    done();
  }));
  const address = await new Promise((done, fail) => {
    child.once('error', fail);
    child.once('exit', (status, signal) => fail(new Error(
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
          if (match) done(new URL(match.groups.address));
        }
      });
    }
  });
  assert.equal(address.port, port, 'qualification must reach its isolated listener');
  cli(['credential', 'endpoint', 'declare', address.origin]);
  cli(['browser', 'install', '--binary', binary]);
  // Added after installation, so the grant covers none of its fields.
  const ungranted = `native-host-ungranted-${randomUUID()}`;
  cli(['set', ungranted, '--type', 'login'], JSON.stringify({ schema: 'skarbiec.item.v2', kind: 'login',
    fields: { username: `user-${randomUUID()}`, password: `secret-${randomUUID()}` },
    context: { name: ungranted, domains: [domain] } }));

  const session = host('requests', Buffer.concat([
    frame({ action: 'list', domain }),
    frame({ action: 'fill', id: login }),
    frame({ action: 'fill', id: ungranted }),
    frame({ action: 'fill' }),
    frame({}),
    frame({ action: 'search', text: domain.toUpperCase() }),
    frame({ action: 'search', text: `nothing-${randomUUID()}` }),
    frame({ action: 'search' }),
  ]));
  assert.equal(session.status, source.status, `native host: ${session.stderr}`);
  const [listed, filled, refused, noId, noAction, searched, unmatched, noText] = session.replies;
  // Search reads every login, whatever the tab, and matches regardless of case.
  assert.equal(searched.ok, true, JSON.stringify(searched));
  assert.deepEqual(searched.logins.map(row => row.id), [login]);
  assert.deepEqual(unmatched.logins, []);
  assert.match(noText.error, /text required/);
  assert.equal(listed.ok, true, JSON.stringify(listed));
  assert.deepEqual(listed.logins.map(row => row.id), [login]);
  assert.equal(filled.ok, true, JSON.stringify(filled));
  assert.equal(filled.totp, null);
  assert.match(filled.totp_unavailable, /totp seed/);
  assert.ok(filled.totp_unavailable.includes(login), 'the unusable seed is named by its item');
  assert.equal(refused.ok, false);
  assert.match(refused.error, /skarbiec API \/v1\/items\/read/);
  assert.equal(noId.error, 'id required');
  assert.equal(noAction.error, 'action required');

  // An offered login waits sealed in the donation inbox until the owner
  // accepts it; accepted, it opens with the password offered.
  const offeredSite = `offered-${randomUUID()}.test`;
  const offeredPassword = `offered-secret-${randomUUID()}`;
  const offering = host('offer', Buffer.concat([
    frame({ action: 'offer', site: offeredSite, username: 'me', password: offeredPassword }),
    frame({ action: 'offer', site: 'not a host', username: 'me', password: offeredPassword }),
  ]));
  assert.equal(offering.status, source.status, `native host: ${offering.stderr}`);
  const [offered, badSite] = offering.replies;
  assert.equal(offered.ok, true, JSON.stringify(offered));
  assert.equal(offered.status, 'pending');
  assert.equal(badSite.ok, false);
  const pending = JSON.parse(cli(['donation', 'list']));
  assert.ok(pending.some(row => row.id === offered.donation_id && row.item_id === offered.id),
    `the offer waits in the inbox: ${JSON.stringify(pending)}`);
  assert.ok(!readFileSync(join(root, 'audit.jsonl'), 'utf8').includes(offeredPassword), 'the journal holds no offered password');
  cli(['donation', 'accept', offered.donation_id]);
  assert.equal(cli(['get', offered.id, '--field', 'password']).trim(), offeredPassword);

  const declared = frame({ action: 'fill', id: login });
  const cut = host('cut frame', declared.subarray(declared.length - declared.length,
    declared.length - Uint32Array.BYTES_PER_ELEMENT));
  assert.notEqual(cut.status, source.status, 'a frame cut short must end the host with a refusal');
  assert.match(cut.stderr, /native message ended after \d+ of its declared \d+ bytes/);

  child.kill();
  await closed;
  const gone = host('API gone', frame({ action: 'fill', id: login }));
  assert.equal(gone.status, source.status, `native host: ${gone.stderr}`);
  const [goneReply] = gone.replies;
  assert.equal(goneReply.ok, false);
  assert.ok(goneReply.error.includes(`/v1/items/read at the serve ${address.host}`),
    `a fill against an absent API names the request: ${goneReply.error}`);
  assert.match(goneReply.error, /refused/i, `the reply carries why the API was not reached: ${goneReply.error}`);
  report.observedFinalState = { listed: listed.logins.map(row => row.id),
    totpUnavailable: filled.totp_unavailable, ungrantedRefusal: refused.error,
    cutFrame: cut.stderr.trim(), apiGone: goneReply.error };
  report.passed = true;
} catch (error) {
  report.failure = error.stack ?? String(error);
  throw error;
} finally {
  if (child) {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  }
  const cleanup = spawnSync('gpgconf', ['--homedir', keyring, '--kill', 'all'],
    { cwd: repo, env, encoding: 'utf8' });
  report.commands.push({ program: 'gpgconf', args: ['--homedir', keyring, '--kill', 'all'],
    status: cleanup.status, stderr: cleanup.stderr, error: cleanup.error?.message });
  if (cleanup.status !== source.status || cleanup.error) {
    report.passed = false;
    report.cleanupFailure = cleanup.error?.message ?? cleanup.stderr;
  }
  rmSync(keyring, { recursive: true, force: true });
  writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, '\t'));
  assert.equal(report.passed, true, `native host journey report: ${join(root, 'report.json')}`);
}
