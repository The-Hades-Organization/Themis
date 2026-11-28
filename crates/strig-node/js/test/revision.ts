// Read-your-writes helpers and the remote client's `minRevision`. `run.js` imports this file.
import assert from 'node:assert/strict';
import { revisionReached, parseRevision } from '../dist/protocol.js';
import { RemoteClient } from '../dist/remote.js';
import type { CheckInput } from '../dist/remote.js';
import { harness } from './web-suite.js';

const { test } = harness('revision');
const input: CheckInput = { subject: { kind: 'user', id: 'a' }, permission: 'document.view', resource: { path: [] } };
const allowAt = (revision?: string) => ({ decision: { effect: 'allow', reason: { kind: 'no_applicable_grant' }, warnings: [] }, ...(revision ? { revision } : {}) });

await test('revisionReached compares by scope and value, never trusts a missing revision', () => {
  assert.equal(revisionReached('t@5', 't@5'), 'yes');
  assert.equal(revisionReached('t@5', 't@9'), 'yes');
  assert.equal(revisionReached('t@5', 't@4'), 'behind');
  assert.equal(revisionReached('t@5', 'u@9'), 'other_scope');
  assert.equal(revisionReached('t@5', undefined), 'untracked');
  assert.equal(revisionReached('t@5', 'garbage'), 'untracked');
  assert.equal(revisionReached('a@b@12', 'a@b@12'), 'yes', 'the scope may contain @');
  assert.equal(parseRevision('t@-1'), undefined);
  assert.equal(revisionReached('t@18446744073709551615', 't@18446744073709551614'), 'behind', 'u64 range');
});

await test('remote: minRevision goes in the header and the answer must prove it', async () => {
  const seen: Array<string | null> = [];
  const fetchWith = (revision?: string) => async (_url: unknown, init?: RequestInit) => {
    seen.push(new Headers(init?.headers).get('x-strig-min-revision'));
    return new Response(JSON.stringify(allowAt(revision)), { status: 200 });
  };
  const ok = await new RemoteClient({ url: 'http://x', fetch: fetchWith('t@7') as typeof fetch, minRevision: 't@5' }).check(input);
  assert.equal(ok.allowed, true);
  assert.equal(ok.revision, 't@7');
  assert.deepEqual(seen, ['t@5']);

  const old = await new RemoteClient({ url: 'http://x', fetch: fetchWith('t@4') as typeof fetch }).check({ ...input, minRevision: 't@5' });
  assert.equal(old.allowed, false);
  assert.equal(old.failure?.code, 'revision_not_reached');

  const blind = await new RemoteClient({ url: 'http://x', fetch: fetchWith() as typeof fetch, minRevision: 't@5' }).check(input);
  assert.equal(blind.allowed, false, 'a server that ignores the requirement is a deny');

  const other = await new RemoteClient({ url: 'http://x', fetch: fetchWith('u@9') as typeof fetch, minRevision: 't@5' }).check(input);
  assert.equal(other.failure?.code, 'revision_mismatch');

  assert.throws(() => new RemoteClient({ url: 'http://x', minRevision: 'nope' }), TypeError);
});

await test('remote: batch carries the requirement and a 503 revision refusal does not open the circuit', async () => {
  const bodies: unknown[] = [];
  const behind = async (_url: unknown, init?: RequestInit) => {
    bodies.push(JSON.parse(String(init?.body)));
    return new Response(JSON.stringify({ error: { code: 'revision_not_reached' } }), { status: 503 });
  };
  const client = new RemoteClient({ url: 'http://x', fetch: behind as typeof fetch, breaker: { failureThreshold: 1 } });
  const results = await client.checkBatch([input, input], { minRevision: 't@5' });
  assert.deepEqual(results.map((r) => r.allowed), [false, false]);
  assert.equal(results[0]!.failure?.code, 'revision_not_reached');
  for (let i = 0; i < 3; i++) await client.check({ ...input, minRevision: 't@5' });
  assert.equal(client.breaker.state, 'closed');
  assert.ok(!('minRevision' in (bodies[0] as { checks: object[] }).checks[0]!), 'camelCase never reaches the wire');
});

await test('remote: batch answers take the revision of the whole batch', async () => {
  const ok = async () => new Response(JSON.stringify({ results: [allowAt(), allowAt()], revision: 't@6' }), { status: 200 });
  const results = await new RemoteClient({ url: 'http://x', fetch: ok as typeof fetch }).checkBatch([input, input], { minRevision: 't@5' });
  assert.deepEqual(results.map((r) => r.allowed), [true, true]);
  assert.equal(results[0]!.revision, 't@6');
});
