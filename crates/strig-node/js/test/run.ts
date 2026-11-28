// Roda em Node (`node dist-test/run.js`) e em Bun (`bun dist-test/run.js`).
// Variáveis opcionais: STRIG_RUST_SERVER (url do example `server` do strig-axum),
// STRIG_REDIS_URL (Redis; usado com o RedisClient do Bun), STRIG_PG_URL (Postgres; usa o pacote `pg`).
import assert from 'node:assert/strict';
import { PermissionClient } from '../dist/client.js';
import type { Grant, Subject } from '../dist/index.js';
import { load, scopeFromString } from '../dist/node.js';
import './binding040.js';
import './hooks.js';
import './batch.js';
import './revision.js';
import './fields.js';
import './why-not.js';
import './audit.js';
import './audit-proofs.js';
import './dsl.js';
import './types-gen.js';
import './web-core.js';
import './web-express.js';
import './web-fastify.js';
import './web-nestjs.js';
import './frameworks.js';
import './web-routes.js';
import './store.js';
import './approvals.js';
import './elevation.js';
import './separation.js';
import './orm.js';
import { Hub, change, engineProvider, memoryTransport, openSession, pgTransport, pipeSse, redisTransport, sseResponse } from '../dist/server.js';

interface BunServer {
  port: number;
  stop(force?: boolean): void;
}
interface BunSocket {
  data: { scopes: ReturnType<typeof scopeFromString>[]; session?: { handle(message: string): Promise<void>; close(): void } };
  send(text: string): void;
}
interface BunRuntime {
  version: string;
  serve(options: {
    port: number;
    fetch(req: Request, srv: { upgrade(req: Request, options: { data: BunSocket['data'] }): boolean }): Response | undefined;
    websocket: { open(ws: BunSocket): void; message(ws: BunSocket, text: unknown): void; close(ws: BunSocket): void };
  }): BunServer;
  RedisClient?: new (url: string) => { publish(channel: string, message: string): unknown; subscribe(channel: string, listener: (message: string) => void): unknown; unsubscribe(channel: string): unknown };
}
const Bun = (globalThis as unknown as { Bun?: BunRuntime }).Bun;

const runtime = Bun ? `bun ${Bun.version}` : `node ${process.version}`;
let failures = 0;
async function test(name: string, fn: () => Promise<void> | void): Promise<void> {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures += 1;
    console.log(`not ok - ${name}\n  ${(error as Error | undefined)?.stack ?? error}`);
  }
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(check: () => unknown, ms = 3000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (check()) return;
    await sleep(20);
  }
  throw new Error('condição não atingida a tempo');
}

const SPEC = {
  catalog: {
    targetKinds: ['project', 'document'],
    broadTargets: ['org'],
    permissions: [
      { key: 'project.view', targets: ['project'] },
      { key: 'project.edit', targets: ['project'] },
      { key: 'document.view', targets: ['project', 'document'], impliedBy: ['project.view'] },
    ],
  },
  roles: [{ role: 'admin', inherits: ['member'] }],
};
const memberGrant: Grant = { id: 'g1', subject: { kind: 'role', id: 'member' }, permission: 'project.view', target: { kind: 'project' }, effect: 'allow' };
const p1 = scopeFromString('project:p1/org:o1');
const doc = scopeFromString('document:d1/project:p1/org:o1');
const admin: Subject = { kind: 'user', id: 'ana', roles: [{ role: 'admin' }] };

console.log(`# ${runtime}`);

for (const backend of ['native', 'wasm'] as const) {
  await test(`${backend}: decisão, capacidades, governança e auditoria`, async () => {
    const { Engine, Context, auditEstimate, backend: got } = await load({ backend });
    assert.equal(got, backend);
    const engine = new Engine(SPEC);
    const ctx = new Context({ grants: [memberGrant] });
    assert.equal(ctx.size, 1);
    const request = { subject: admin, permission: 'document.view', resource: doc };
    assert.equal(engine.check(ctx, request), true);
    const decision = engine.decide(ctx, request);
    assert.equal(decision.effect, 'allow');
    assert.equal((decision.reason as Extract<typeof decision.reason, { kind: 'grant' }>).grantId, 'g1');
    assert.equal(engine.check(ctx, { ...request, permission: 'project.edit' }), false);
    assert.equal(engine.capabilities(ctx, admin, p1).grants.length, 1);
    const explained = engine.explain(ctx, request);
    assert.equal(explained.decision.effect, 'allow');
    assert.equal(explained.grants[0]?.verdict.kind, 'candidate');
    assert.deepEqual(explained.roles, ['admin', 'member']);
    assert.throws(() => engine.validateGrant({ ...memberGrant, permission: 'nope' }), /desconhecida/);
    assert.throws(() => new Engine({ catalog: { targetKinds: [], permissions: [{ key: 'Bad', targets: [] }] } }), /inválid/);

    const out = engine.apply({
      actor: admin,
      current: ctx.grants(),
      mutation: { add: { ...memberGrant, id: 'g2', permission: 'project.edit' } },
      invariants: [{ kind: 'catalog_conformance' }, { kind: 'no_self_management' }],
      audit: { level: 'forensic' },
      meta: { ip: '203.0.113.1' },
    });
    assert.equal(out.ok, false, 'admin herda member: autogestão');
    const outAudit = out.audit as { outcome: string; hash: string; at: number; action?: string };
    assert.equal(outAudit.outcome, 'rejected');
    assert.equal(outAudit.hash.length, 64);
    assert.ok(outAudit.at > 1.7e12, 'relógio do runtime');

    const ok = engine.apply({ actor: { kind: 'user', id: 'root' }, current: [], mutation: { add: memberGrant }, audit: { level: 'minimal' } });
    assert.equal(ok.ok, true);
    assert.equal(ok.grants?.length, 1);

    const bob: Subject = { kind: 'user', id: 'bob' };
    const assigned = engine.apply({
      actor: admin,
      current: [memberGrant],
      mutation: { assign_role: { subject: bob, role: { role: 'member' } } },
      invariants: [{ kind: 'catalog_conformance' }, { kind: 'no_self_management' }],
      audit: { level: 'standard' },
    });
    assert.equal(assigned.ok, true);
    assert.deepEqual(assigned.subject?.roles, [{ role: 'member' }]);
    assert.equal((assigned.audit as { action?: string }).action, 'role_assign');
    const ownRevoke = engine.apply({
      actor: admin,
      current: [memberGrant],
      mutation: { revoke_role: { subject: admin, role: { role: 'admin' } } },
      invariants: [{ kind: 'no_self_management' }],
    });
    assert.equal(ownRevoke.ok, false);
    assert.equal(ownRevoke.violations?.[0]?.invariant, 'no_self_management');
    assert.ok(auditEstimate('forensic', 1e6) > auditEstimate('minimal', 1e6));
  });
}

const strig = await load();
const engine = new strig.Engine(SPEC);
const grants: Grant[] = [];
const provider = engineProvider({ engine, Context: strig.Context, loadGrants: () => grants });

await test('sessão JS: capacidades, mudança, watch e resync', async () => {
  const hub = new Hub();
  const messages: any[] = [];
  const session = openSession({ hub, subject: { kind: 'user', id: 'bob' }, scopes: [p1], provider, heartbeatMs: 0, send: (m) => messages.push(m) });
  await session.ready;
  assert.deepEqual(messages.map((m) => m.type), ['hello', 'capabilities']);
  grants.push({ ...memberGrant, id: 'bob-edit', subject: { kind: 'user', id: 'bob' }, permission: 'project.edit' });
  await hub.publish(change('grants', { kind: 'project', id: 'p2' }));
  await hub.publish(change('grants', { kind: 'project', id: 'p1' }));
  await until(() => messages.length === 4);
  assert.equal(messages[2].type, 'change');
  assert.equal(messages[3].set.grants.length, 1);
  await session.handle(JSON.stringify({ type: 'watch', scopes: [scopeFromString('project:p3')] }));
  assert.equal(messages.at(-1).scope.path[0].id, 'p3');
  hub.deliver(change('resync', { kind: 'global' }));
  await until(() => messages.some((m) => m.type === 'resync'));
  session.close();
});

await test('hubs JS trocam mudanças pelo transporte, sem eco', async () => {
  const transport = memoryTransport();
  const a = new Hub({ origin: 'a', transport });
  const b = new Hub({ origin: 'b', transport });
  await a.startRelay();
  await b.startRelay();
  const atA: unknown[] = [];
  const atB: { origin: string }[] = [];
  a.subscribe((c) => atA.push(c));
  b.subscribe((c) => atB.push(c as { origin: string }));
  await a.publish(change('roles', { kind: 'org', id: 'o1' }, { subject: 'bob' }));
  await until(() => atB.length === 1);
  await sleep(30);
  assert.equal(atA.length, 1);
  assert.equal(atB[0]?.origin, 'a');
});

async function serveJs(hub: Hub): Promise<{ base: string; ws: boolean; stop: () => unknown }> {
  const subject: Subject = { kind: 'user', id: 'bob' };
  if (Bun) {
    const server = Bun.serve({
      port: 0,
      fetch(req, srv) {
        const url = new URL(req.url);
        const scopes = url.searchParams.getAll('scope').map(scopeFromString);
        if (url.pathname === '/ws') return srv.upgrade(req, { data: { scopes } }) ? undefined : new Response('upgrade', { status: 400 });
        return sseResponse({ hub, subject, scopes, provider, heartbeatMs: 0 });
      },
      websocket: {
        open(ws) {
          ws.data.session = openSession({ hub, subject, scopes: ws.data.scopes, provider, heartbeatMs: 0, send: (m) => ws.send(JSON.stringify(m)) });
        },
        message(ws, text) {
          ws.data.session?.handle(String(text));
        },
        close(ws) {
          ws.data.session?.close();
        },
      },
    });
    return { base: `http://127.0.0.1:${server.port}`, ws: true, stop: () => server.stop(true) };
  }
  const http = await import('node:http');
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    pipeSse(res, { hub, subject, scopes: url.searchParams.getAll('scope').map(scopeFromString), provider, heartbeatMs: 0 });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { base: `http://127.0.0.1:${(server.address() as { port: number }).port}`, ws: false, stop: () => (server.closeAllConnections(), server.close()) };
}

async function exerciseClient({ url, transport, mutate, label }: { url: string; transport: 'sse' | 'websocket'; mutate: () => Promise<void>; label: string }) {
  const client = new PermissionClient({ url, transport, scopes: [p1], strig, engine });
  const updates: unknown[] = [];
  client.on('capabilities', (m) => updates.push(m));
  client.connect();
  await until(() => updates.length >= 1);
  const before = client.can('project.edit', doc);
  await mutate();
  await until(() => client.can('project.edit', doc), 4000);
  client.close();
  assert.equal(before, false, `${label}: sem permissão antes`);
}

await test('cliente SSE contra servidor JS', async () => {
  grants.length = 0;
  const hub = new Hub();
  const server = await serveJs(hub);
  try {
    await exerciseClient({
      url: `${server.base}/events`,
      transport: 'sse',
      label: 'sse-js',
      mutate: async () => {
        grants.push({ ...memberGrant, id: 'bob-edit', subject: { kind: 'user', id: 'bob' }, permission: 'project.edit' });
        await hub.publish(change('grants', { kind: 'project', id: 'p1' }));
      },
    });
  } finally {
    server.stop();
  }
});

async function serveRevisions(hub: Hub, state: { rev: number }) {
  const http = await import('node:http');
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    pipeSse(res, {
      hub,
      subject: { kind: 'user', id: 'bob' },
      scopes: url.searchParams.getAll('scope').map(scopeFromString),
      provider,
      heartbeatMs: 0,
      revision: () => `tenant@${state.rev}`,
      minRevision: url.searchParams.get('min_revision') ?? undefined,
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  return { url: `http://127.0.0.1:${port}/events`, stop: () => (server.closeAllConnections(), server.close()) };
}

await test('leitura da própria escrita: cliente atrás nega e decide quando a revisão chega', async () => {
  grants.length = 0;
  grants.push({ ...memberGrant, id: 'bob-edit', subject: { kind: 'user', id: 'bob' }, permission: 'project.edit' });
  const hub = new Hub();
  const state = { rev: 1 };
  const server = await serveRevisions(hub, state);
  try {
    const client = new PermissionClient({ url: server.url, scopes: [p1], strig, engine, minRevision: 'tenant@2' });
    const errors: string[] = [];
    client.on('error', (e) => errors.push(e.message));
    client.connect();
    await until(() => errors.includes('revision_not_reached'));
    assert.equal(client.can('project.edit', doc), false, 'atrás: sem decisão, nega');
    assert.equal(client.behind(), true);
    state.rev = 2;
    await hub.publish(change('grants', { kind: 'project', id: 'p1' }));
    await until(() => client.can('project.edit', doc), 4000);
    assert.equal(client.behind(), false);
    assert.equal(client.revision(p1), 'tenant@2');
    client.close();
  } finally {
    server.stop();
  }
});

await test('leitura da própria escrita: requireRevision em cliente já conectado e escopo de outro dado', async () => {
  grants.length = 0;
  grants.push({ ...memberGrant, id: 'bob-edit', subject: { kind: 'user', id: 'bob' }, permission: 'project.edit' });
  const hub = new Hub();
  const state = { rev: 1 };
  const server = await serveRevisions(hub, state);
  try {
    const client = new PermissionClient({ url: server.url, scopes: [p1], strig, engine });
    const updates: unknown[] = [];
    client.on('capabilities', (m) => updates.push(m));
    client.connect();
    await until(() => client.can('project.edit', doc));
    client.requireRevision('tenant@3');
    assert.equal(client.can('project.edit', doc), false, 'exigiu a revisão: nega até alcançá-la');
    assert.equal(client.minRevision, 'tenant@3');
    client.requireRevision('tenant@2');
    assert.equal(client.minRevision, 'tenant@3', 'a exigência nunca recua');
    await new Promise((r) => setTimeout(r, 100));
    state.rev = 3;
    await hub.publish(change('grants', { kind: 'project', id: 'p1' }));
    await until(() => client.can('project.edit', doc), 4000);
    client.requireRevision('other@1');
    assert.equal(client.can('project.edit', doc), false, 'revisão de outro escopo nega');
    assert.throws(() => client.requireRevision('sem-arroba'));
    client.close();
  } finally {
    server.stop();
  }
});

if (Bun) {
  await test('cliente WebSocket contra Bun.serve', async () => {
    grants.length = 0;
    const hub = new Hub();
    const server = await serveJs(hub);
    try {
      await exerciseClient({
        url: `${server.base.replace('http', 'ws')}/ws`,
        transport: 'websocket',
        label: 'ws-bun',
        mutate: async () => {
          grants.push({ ...memberGrant, id: 'bob-edit', subject: { kind: 'user', id: 'bob' }, permission: 'project.edit' });
          await hub.publish(change('grants', { kind: 'project', id: 'p1' }));
        },
      });
    } finally {
      server.stop();
    }
  });
}

const rust = process.env.STRIG_RUST_SERVER;
if (rust) {
  for (const transport of ['sse', 'websocket'] as const) {
    if (transport === 'websocket' && !globalThis.WebSocket) continue;
    await test(`cliente ${transport} contra o servidor Rust (strig-axum)`, async () => {
      const spec = await (await fetch(`${rust}/spec`)).json();
      const rustEngine = new strig.Engine(spec);
      const user = `u${transport}${Date.now()}`;
      const project = `p${transport}${Date.now()}`;
      const scope = scopeFromString(`project:${project}/org:o1`);
      const resource = scopeFromString(`document:d1/project:${project}/org:o1`);
      const client = new PermissionClient({
        url: transport === 'sse' ? `${rust}/events` : `${rust.replace('http', 'ws')}/ws`,
        transport,
        scopes: [scope],
        strig,
        engine: rustEngine,
        headers: { 'x-user': user },
      });
      const updates: unknown[] = [];
      client.on('capabilities', (m) => updates.push(m));
      client.connect();
      await until(() => updates.length >= 1);
      // WebSocket do navegador não manda cabeçalho próprio: o servidor de demonstração cai em `alice`.
      const who = transport === 'sse' ? user : 'alice';
      assert.equal(client.can('project.edit', resource), false);
      const res = await fetch(`${rust}/grant/${project}/${who}/project.edit`, { method: 'POST' });
      assert.equal(res.status, 200);
      await until(() => client.can('project.edit', resource), 4000);
      client.close();
    });
  }
}

const redisUrl = process.env.STRIG_REDIS_URL;
if (redisUrl && Bun?.RedisClient) {
  await test('redisTransport com o RedisClient do Bun', async () => {
    const channel = `strig:js:${process.pid}`;
    const RedisClient = Bun.RedisClient!;
    const make = () => new RedisClient(redisUrl);
    const a = new Hub({ origin: 'a', transport: redisTransport({ publisher: make(), subscriber: make(), channel }) });
    const b = new Hub({ origin: 'b', transport: redisTransport({ publisher: make(), subscriber: make(), channel }) });
    await a.startRelay();
    await b.startRelay();
    const atB: { origin: string }[] = [];
    b.subscribe((c) => atB.push(c as { origin: string }));
    await a.publish(change('tuples', { kind: 'project', id: 'p1' }));
    await until(() => atB.length === 1);
    assert.equal(atB[0]?.origin, 'a');
    await a.close();
    await b.close();
  });
}

const pgUrl = process.env.STRIG_PG_URL;
if (pgUrl) {
  const pg = await import('pg').then((m) => m.default ?? m).catch(() => undefined);
  if (pg) {
    await test('pgTransport com o pacote pg, incluindo NOTIFY na transação', async () => {
      const channel = `strig_js_${process.pid}`;
      const connect = async () => {
        const c = new pg.Client({ connectionString: pgUrl });
        await c.connect();
        return c;
      };
      const [pubA, lisA, pubB, lisB] = await Promise.all([connect(), connect(), connect(), connect()]);
      const a = new Hub({ origin: 'a', transport: pgTransport({ client: pubA, listener: lisA, channel }) });
      const b = new Hub({ origin: 'b', transport: pgTransport({ client: pubB, listener: lisB, channel }) });
      await a.startRelay();
      await b.startRelay();
      const atB = [];
      b.subscribe((c) => atB.push(c));
      await a.publish(change('grants', { kind: 'org', id: 'o1' }));
      await until(() => atB.length === 1);
      await pubA.query('BEGIN');
      await pubA.query('SELECT pg_notify($1, $2)', [channel, JSON.stringify(change('grants', { kind: 'org', id: 'o2' }))]);
      await sleep(200);
      assert.equal(atB.length, 1, 'NOTIFY não sai antes do COMMIT');
      await pubA.query('COMMIT');
      await until(() => atB.length === 2);
      await a.close();
      await b.close();
      await Promise.all([pubA, lisA, pubB, lisB].map((c) => c.end()));
    });
  } else {
    console.log('# pacote pg ausente: teste do Postgres pulado');
  }
}

console.log(failures ? `# ${failures} falha(s)` : '# tudo ok');
process.exit(failures || process.exitCode ? 1 : 0);
