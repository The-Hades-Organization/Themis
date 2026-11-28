// Access recertification: campaign, keep, revoke, delegate, reviewer rules, close with the default action, report
// and the JSON store. Runs on both backends (N-API and wasm); `run.js` imports this file.
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryRecertStore, Recertifications, RecertStoreError } from '../dist/approvals.js';
import type { ApplyInput, CampaignSpec, Grant, InvariantSpec, Subject } from '../dist/index.js';
import { load } from '../dist/node.js';
import { openJsonStore } from '../dist/store.js';

let failures = 0;
async function test(name: string, fn: (dir: string) => unknown) {
  const dir = await mkdtemp(join(tmpdir(), 'strig-recert-'));
  try {
    await fn(dir);
    console.log(`ok - ${name}`);
  } catch (error) {
    failures += 1;
    process.exitCode = 1;
    console.log(`not ok - ${name}\n  ${error instanceof Error ? error.stack : error}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const SPEC = {
  catalog: {
    targetKinds: ['project'],
    broadTargets: ['org'],
    permissions: [
      { key: 'project.view', targets: ['project'] },
      { key: 'project.edit', targets: ['project'] },
      { key: 'grants.manage', targets: ['project'] },
    ],
  },
};
const DAY = 86_400_000;
const T0 = 1_700_000_000_000;
const DUE = T0 + 7 * DAY;
const project = { path: [{ kind: 'project', id: 'p1' }] };
const admin = (id: string): Subject => ({ kind: 'user', id, roles: [{ role: 'admin' }] });
const grant = (id: string, user: string, permission = 'project.edit'): Grant => ({
  id,
  subject: { kind: 'user', id: user },
  permission,
  target: { kind: 'project', id: 'p1' },
  effect: 'allow',
});
const adminGrant: Grant = { id: 'adm', subject: { kind: 'role', id: 'admin' }, permission: 'grants.manage', target: { kind: 'project' }, effect: 'allow' };
const invariants: InvariantSpec[] = [{ kind: 'catalog_conformance' }];
const current = [adminGrant, grant('ana-edit', 'ana'), grant('caio-edit', 'caio')];
const spec = (id: string, extra: Partial<CampaignSpec> = {}): CampaignSpec => ({
  id,
  reviewer: { kind: 'permission', permission: 'grants.manage', resource: project },
  reviewerPermission: 'grants.manage',
  reviewerResource: project,
  dueAt: DUE,
  keepPeriodMs: 30 * DAY,
  scope: { permissions: ['project.edit'] },
  ...extra,
});

for (const backend of ['native', 'wasm'] as const) {
  const setup = async () => {
    const { Engine } = await load({ backend });
    const store = new MemoryRecertStore();
    const audit: ApplyInput['audit'] = { level: 'forensic' };
    const flow = new Recertifications(new Engine(SPEC), store, { invariants, audit });
    return { flow, store };
  };

  await test(`${backend}: abrir gera um item por grant do escopo, manter certifica e revogar tira o grant`, async () => {
    const { flow, store } = await setup();
    const opened = await flow.open(spec('c1'), admin('bia'), [], current, { now: T0 });
    assert.ok(opened.ok && opened.campaign);
    assert.deepEqual(opened.campaign.items.map((i) => i.id), ['grant:ana-edit', 'grant:caio-edit']);

    const kept = await flow.decide('c1', 'grant:ana-edit', { action: 'keep' }, admin('bia'), current, { now: T0 + 1 });
    assert.ok(kept.ok);
    assert.equal(kept.item?.state.state, 'kept');

    let persisted: Grant[] | undefined;
    const revoked = await flow.decide('c1', 'grant:caio-edit', { action: 'revoke' }, admin('bia'), current, {
      now: T0 + 2,
      reason: 'left the team',
      persist: (r) => {
        persisted = r.grants;
      },
    });
    assert.ok(revoked.ok);
    assert.ok(persisted && !persisted.some((g) => g.id === 'caio-edit') && persisted.some((g) => g.id === 'ana-edit'));
    assert.equal((await store.get('c1'))?.revision, 2);

    const report = await flow.report('c1');
    assert.equal(report.kept, 1);
    assert.equal(report.revoked, 1);
    assert.equal(report.open, 0);
  });

  await test(`${backend}: revisor sem a permissão é recusado e a campanha fica como estava`, async () => {
    const { flow, store } = await setup();
    await flow.open(spec('c1'), admin('bia'), [], current, { now: T0 });
    const stranger = await flow.decide('c1', 'grant:ana-edit', { action: 'keep' }, { kind: 'user', id: 'zed' }, current, { now: T0 + 1 });
    assert.ok(!stranger.ok && stranger.code === 'REFUSED');
    assert.equal((await store.get('c1'))?.revision, 0);
  });

  await test(`${backend}: o revisor não revisa o próprio acesso`, async () => {
    const { flow } = await setup();
    const own = [adminGrant, grant('bia-edit', 'bia')];
    await flow.open(spec('c1'), admin('opener'), [], own, { now: T0 });
    const self = await flow.decide('c1', 'grant:bia-edit', { action: 'keep' }, admin('bia'), own, { now: T0 + 1 });
    assert.ok(!self.ok && self.code === 'REFUSED');
  });

  await test(`${backend}: delegar passa o item a quem tem a permissão`, async () => {
    const { flow } = await setup();
    await flow.open(spec('c1'), admin('bia'), [], current, { now: T0 });
    const delegated = await flow.decide('c1', 'grant:ana-edit', { action: 'delegate', to: admin('dan') }, admin('bia'), current, {
      now: T0 + 1,
      reason: 'dan owns this project',
    });
    assert.ok(delegated.ok);
    assert.equal(delegated.item?.assignee, 'dan');
    const back = await flow.decide('c1', 'grant:ana-edit', { action: 'keep' }, admin('dan'), current, { now: T0 + 2 });
    assert.ok(back.ok);
    assert.equal((await flow.report('c1')).delegated, 1);
  });

  await test(`${backend}: no prazo a ação padrão expira o que ninguém revisou, e depois disso a campanha está fechada`, async () => {
    const { flow, store } = await setup();
    await flow.open(spec('c1'), admin('bia'), [], current, { now: T0 });
    await flow.decide('c1', 'grant:ana-edit', { action: 'keep' }, admin('bia'), current, { now: T0 + 1 });

    const early = await flow.close('c1', admin('bia'), current, { now: DUE - 1 });
    assert.ok(!early.ok && early.code === 'REFUSED');

    let persisted: Grant[] | undefined;
    const closed = await flow.close('c1', admin('bia'), current, {
      now: DUE,
      persist: (r) => {
        persisted = r.grants;
      },
    });
    assert.ok(closed.ok);
    assert.ok(persisted && !persisted.some((g) => g.id === 'caio-edit'));
    assert.equal(closed.report?.expired, 1);
    assert.equal((await store.get('c1'))?.status.state, 'closed');
    assert.deepEqual(await flow.openCampaigns(), []);

    const again = await flow.close('c1', admin('bia'), current, { now: DUE + 1 });
    assert.ok(!again.ok && again.code === 'CLOSED');
  });

  await test(`${backend}: cada passo é auditado em cadeia`, async () => {
    const { flow } = await setup();
    const opened = await flow.open(spec('c1'), admin('bia'), [], current, { now: T0 });
    const kept = await flow.decide('c1', 'grant:ana-edit', { action: 'keep' }, admin('bia'), current, { now: T0 + 1 });
    assert.ok(opened.audits.length > 0 && kept.audits.length > 0);
    assert.equal(kept.audits[0]?.prevHash, opened.audits.at(-1)?.hash);
  });

  await test(`${backend}: o store JSON guarda a campanha e recusa escrita velha`, async (dir) => {
    const { Engine } = await load({ backend });
    const file = await openJsonStore({ path: join(dir, 'store.json'), createIfMissing: true });
    const flow = new Recertifications(new Engine(SPEC), file.recertStore, { invariants });
    await flow.open(spec('c1'), admin('bia'), [], current, { now: T0 });
    const stale = (await file.recertStore.get('c1'))!;
    await flow.decide('c1', 'grant:ana-edit', { action: 'keep' }, admin('bia'), current, { now: T0 + 1 });
    assert.equal((await file.recertStore.get('c1'))?.revision, 1);
    await assert.rejects(
      async () => file.recertStore.update({ ...stale, revision: 1 }),
      (error) => error instanceof RecertStoreError && error.code === 'RECERT_STALE',
    );
    assert.equal((await file.recertStore.list()).length, 1);
  });
}

if (failures > 0) process.exitCode = 1;
