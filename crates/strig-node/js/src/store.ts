// Persistence in a single JSON file, for systems with neither Postgres nor Redis: the grants and the role
// assignments live in `{ version, grants, roles }`. Node and Bun only (it uses `node:fs`); import it from
// `@the-hades-organization/strig/store`.
//
// Writes are atomic (temp file in the same directory, fsync, rename) and serialised: by a promise queue between
// calls of one process and by a lock file (`<file>.lock`, created with `O_EXCL`) between processes. Every
// mutation re-reads the file under the lock, so two processes never overwrite each other. A file that is missing,
// corrupt or of an unknown version is an error on load; the store never starts empty on its own.
import { randomBytes } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, openSync, watch as fsWatch } from 'node:fs';
import type { FSWatcher } from 'node:fs';
import { open, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { hostname } from 'node:os';
import { basename, dirname, resolve } from 'node:path';
import { PendingStoreError, RecertStoreError, checkRecertUpdate } from './approvals.js';
import type { Approvals, DecideOptions, PendingStore, RecertStore } from './approvals.js';
import type { ApplyInput, ApplyResult, Campaign, Grant, PendingRequest, ResolveResult, RoleAssignment, Subject } from './index.js';

/** The only file version this store reads and writes. */
export const STORE_VERSION = 1;

export type StoreErrorCode =
  /** The file does not exist and `createIfMissing` is off. */
  | 'STORE_NOT_FOUND'
  /** The file is not valid JSON or does not have the expected shape. */
  | 'STORE_CORRUPT'
  /** The file declares a version this release does not know. */
  | 'STORE_VERSION'
  /** The lock file could not be taken within `lockTimeoutMs`. */
  | 'STORE_LOCK_TIMEOUT'
  /** The change was refused before touching the file (an unknown grant id, a duplicate id). */
  | 'STORE_INVALID';

export class JsonStoreError extends Error {
  readonly code: StoreErrorCode;

  constructor(code: StoreErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'JsonStoreError';
    this.code = code;
  }
}

/** What the file holds. `roles` maps a subject id to the role assignments it carries. */
export interface StoreData {
  version: number;
  grants: Grant[];
  roles: Record<string, RoleAssignment[]>;
  /** Requests of the approval flow (`@the-hades-organization/strig/approvals`). Absent in a file that never held one; the version stays 1. */
  pending?: PendingRequest[];
  /** Campaigns of the recertification flow. Absent in a file that never held one; the version stays 1. */
  recert?: Campaign[];
}

export interface JsonFileStoreOptions {
  path: string;
  /** Create the file with no grants and no roles when it does not exist. Off by default: a missing file is `STORE_NOT_FOUND`. */
  createIfMissing?: boolean;
  /** A lock older than this is taken over. Default 30000. */
  lockStaleMs?: number;
  /** How long a write waits for the lock. Default 5000. */
  lockTimeoutMs?: number;
  /** Test hook: runs after the temp file is written and synced, before the rename. A throw leaves the file as it was. */
  beforeRename?: () => void | Promise<void>;
}

export type ApplyMutation = Omit<ApplyInput, 'current'>;

/** The `apply` of the engine; the store only needs this one method. */
export interface Governance {
  apply(input: ApplyInput): ApplyResult;
}

const wait = (ms: number) => new Promise<void>((done) => setTimeout(done, ms));
const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function parse(path: string, text: string): StoreData {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (cause) {
    throw new JsonStoreError('STORE_CORRUPT', `${path} is not valid JSON; fix or restore it, the store will not start empty`, { cause });
  }
  const corrupt = (why: string) => new JsonStoreError('STORE_CORRUPT', `${path}: ${why}`);
  if (!isObject(raw)) throw corrupt('the top level must be an object');
  if (raw.version !== STORE_VERSION) {
    throw new JsonStoreError(
      'STORE_VERSION',
      `${path} has version ${JSON.stringify(raw.version)}; this release reads only version ${STORE_VERSION}`,
    );
  }
  if (!Array.isArray(raw.grants)) throw corrupt('`grants` must be an array');
  const ids = new Set<string>();
  for (const grant of raw.grants) {
    if (!isObject(grant) || typeof grant.id !== 'string' || grant.id === '') throw corrupt('every grant needs a string `id`');
    if (ids.has(grant.id)) throw corrupt(`grant id "${grant.id}" appears twice`);
    ids.add(grant.id);
  }
  if (!isObject(raw.roles)) throw corrupt('`roles` must be an object');
  for (const [subject, list] of Object.entries(raw.roles)) {
    if (!Array.isArray(list) || list.some((a) => !isObject(a) || typeof a.role !== 'string')) {
      throw corrupt(`roles of "${subject}" must be an array of assignments with a string \`role\``);
    }
  }
  const data: StoreData = { version: STORE_VERSION, grants: raw.grants as Grant[], roles: raw.roles as Record<string, RoleAssignment[]> };
  if (raw.pending !== undefined) {
    if (!Array.isArray(raw.pending)) throw corrupt('`pending` must be an array');
    const taken = new Set<string>();
    for (const request of raw.pending) {
      if (!isObject(request) || typeof request.id !== 'string' || request.id === '' || !isObject(request.status)) {
        throw corrupt('every pending request needs a string `id` and a `status`');
      }
      if (taken.has(request.id)) throw corrupt(`pending request "${request.id}" appears twice`);
      taken.add(request.id);
    }
    data.pending = raw.pending as PendingRequest[];
  }
  if (raw.recert !== undefined) {
    if (!Array.isArray(raw.recert)) throw corrupt('`recert` must be an array');
    const taken = new Set<string>();
    for (const campaign of raw.recert) {
      if (!isObject(campaign) || typeof campaign.id !== 'string' || campaign.id === '' || !isObject(campaign.status) || !Array.isArray(campaign.items)) {
        throw corrupt('every campaign needs a string `id`, a `status` and `items`');
      }
      if (taken.has(campaign.id)) throw corrupt(`campaign "${campaign.id}" appears twice`);
      taken.add(campaign.id);
    }
    data.recert = raw.recert as Campaign[];
  }
  return data;
}

const sameAssignment = (a: RoleAssignment, b: RoleAssignment): boolean =>
  a.role === b.role &&
  (a.scope?.kind ?? null) === (b.scope?.kind ?? null) &&
  (a.scope?.id ?? null) === (b.scope?.id ?? null) &&
  (a.validFrom ?? null) === (b.validFrom ?? null) &&
  (a.validUntil ?? null) === (b.validUntil ?? null);

export class JsonFileStore {
  readonly path: string;
  private readonly lockPath: string;
  private readonly options: Required<Pick<JsonFileStoreOptions, 'lockStaleMs' | 'lockTimeoutMs'>> & JsonFileStoreOptions;
  private data: StoreData | undefined;
  private queue: Promise<unknown> = Promise.resolve();
  private readonly listeners = new Set<(data: StoreData) => void>();
  private readonly errorListeners = new Set<(error: unknown) => void>();
  private watcher: FSWatcher | undefined;
  private debounce: ReturnType<typeof setTimeout> | undefined;

  constructor(options: JsonFileStoreOptions) {
    this.path = resolve(options.path);
    this.lockPath = `${this.path}.lock`;
    this.options = { lockStaleMs: 30_000, lockTimeoutMs: 5_000, ...options };
  }

  /** Reads the file. Throws `JsonStoreError` when it is missing (without `createIfMissing`), corrupt or of another version. */
  async load(): Promise<this> {
    await this.serial(async () => {
      this.data = await this.readFresh();
    });
    return this;
  }

  /**
   * Reads the file again and replaces the snapshot, after an edit made outside this store. A failure throws and
   * keeps the snapshot that was loaded: a bad file never empties the store.
   */
  async reload(): Promise<StoreData> {
    const next = await this.serial(() => this.readFresh());
    this.data = next;
    for (const listener of [...this.listeners]) listener(this.snapshot());
    return this.snapshot();
  }

  /**
   * Reloads when the file changes (another process, an editor). The directory is watched, not the file, because
   * the atomic rename replaces the inode. A failed reload keeps the last good snapshot and goes to `onError`.
   */
  watch(debounceMs = 50): () => void {
    if (this.watcher) return () => this.unwatch();
    const name = basename(this.path);
    this.watcher = fsWatch(dirname(this.path), (_event, file) => {
      if (file !== null && file !== name) return;
      clearTimeout(this.debounce);
      this.debounce = setTimeout(() => {
        this.reload().catch((error: unknown) => {
          for (const listener of [...this.errorListeners]) listener(error);
        });
      }, debounceMs);
    });
    this.watcher.unref?.();
    return () => this.unwatch();
  }

  unwatch(): void {
    clearTimeout(this.debounce);
    this.watcher?.close();
    this.watcher = undefined;
  }

  /** Called after every reload and every write made by this store. */
  onChange(listener: (data: StoreData) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Called when the watcher could not reload. */
  onError(listener: (error: unknown) => void): () => void {
    this.errorListeners.add(listener);
    return () => this.errorListeners.delete(listener);
  }

  grants(): Grant[] {
    return structuredClone(this.loaded().grants);
  }

  /** The `loadGrants` of `engineProvider`: `engineProvider({ engine, Context, loadGrants: store.loadGrants })`. Every grant; filtering is the engine's job. */
  loadGrants = (): Grant[] => this.grants();

  rolesOf(subjectId: string): RoleAssignment[] {
    return structuredClone(this.loaded().roles[subjectId] ?? []);
  }

  /** `base` with the assignments the file holds for its id; the ones `base` already carries are kept. */
  subject(base: Subject): Subject {
    const stored = base.id === undefined ? [] : this.rolesOf(base.id);
    const roles = [...(base.roles ?? [])];
    for (const assignment of stored) if (!roles.some((r) => sameAssignment(r, assignment))) roles.push(assignment);
    return roles.length === 0 ? base : { ...base, roles };
  }

  snapshot(): StoreData {
    return structuredClone(this.loaded());
  }

  async addGrant(grant: Grant): Promise<void> {
    await this.mutate((data) => {
      if (data.grants.some((g) => g.id === grant.id)) throw new JsonStoreError('STORE_INVALID', `grant "${grant.id}" already exists`);
      data.grants.push(structuredClone(grant));
    });
  }

  async updateGrant(grant: Grant): Promise<void> {
    await this.mutate((data) => {
      const at = data.grants.findIndex((g) => g.id === grant.id);
      if (at < 0) throw new JsonStoreError('STORE_INVALID', `grant "${grant.id}" does not exist`);
      data.grants[at] = structuredClone(grant);
    });
  }

  /** The requests of the approval flow, kept in the same file: `new Approvals(engine, store.pendingStore, options)`. */
  readonly pendingStore: PendingStore = {
    get: async (id) => structuredClone((await this.fresh()).pending?.find((r) => r.id === id)),
    put: (request) =>
      this.mutate((data) => {
        const all = (data.pending ??= []);
        if (all.some((r) => r.id === request.id)) throw new PendingStoreError('PENDING_DUPLICATE', `request "${request.id}" already exists`);
        all.push(structuredClone(request));
      }),
    update: (request) =>
      this.mutate((data) => {
        const at = (data.pending ?? []).findIndex((r) => r.id === request.id);
        const stored = data.pending?.[at];
        if (!stored) throw new PendingStoreError('PENDING_UNKNOWN', `request "${request.id}" does not exist`);
        if (stored.status.state !== 'pending') throw new PendingStoreError('PENDING_NOT_PENDING', `request "${request.id}" is no longer pending`);
        (data.pending as PendingRequest[])[at] = structuredClone(request);
      }),
    annotate: (request) =>
      this.mutate((data) => {
        const at = (data.pending ?? []).findIndex((r) => r.id === request.id);
        const stored = data.pending?.[at];
        if (!stored) throw new PendingStoreError('PENDING_UNKNOWN', `request "${request.id}" does not exist`);
        if (stored.status.state !== request.status.state) throw new PendingStoreError('PENDING_NOT_PENDING', `request "${request.id}" was decided differently`);
        (data.pending as PendingRequest[])[at] = structuredClone(request);
      }),
    list: async () =>
      structuredClone([...((await this.fresh()).pending ?? [])].sort((a, b) => a.requestedAt - b.requestedAt || (a.id < b.id ? -1 : 1))),
  };

  /** The campaigns of the recertification flow, kept in the same file: `new Recertifications(engine, store.recertStore, options)`. */
  readonly recertStore: RecertStore = {
    get: async (id) => structuredClone((await this.fresh()).recert?.find((c) => c.id === id)),
    put: (campaign) =>
      this.mutate((data) => {
        const all = (data.recert ??= []);
        if (all.some((c) => c.id === campaign.id)) throw new RecertStoreError('RECERT_DUPLICATE', `campaign "${campaign.id}" already exists`);
        all.push(structuredClone(campaign));
      }),
    update: (campaign) =>
      this.mutate((data) => {
        const at = (data.recert ?? []).findIndex((c) => c.id === campaign.id);
        checkRecertUpdate(data.recert?.[at], campaign);
        (data.recert as Campaign[])[at] = structuredClone(campaign);
      }),
    list: async () =>
      structuredClone([...((await this.fresh()).recert ?? [])].sort((a, b) => a.openedAt - b.openedAt || (a.id < b.id ? -1 : 1))),
  };

  /**
   * Approves a pending request over the grants the file holds right now. The grants (and, in a role change, the
   * assignments) are persisted before the request is marked approved, so a failed write leaves it pending.
   */
  async approvePending(approvals: Approvals, id: string, approver: Subject, options: Omit<DecideOptions, 'persist'> = {}): Promise<ResolveResult> {
    const current = (await this.fresh()).grants;
    return approvals.approve(id, approver, current, {
      ...options,
      persist: (result) =>
        this.mutate((data) => {
          if (result.grants) data.grants = result.grants;
          if (result.subject?.id !== undefined) {
            const roles = result.subject.roles ?? [];
            if (roles.length === 0) delete data.roles[result.subject.id];
            else data.roles[result.subject.id] = roles;
          }
        }),
    });
  }

  private async fresh(): Promise<StoreData> {
    const data = await this.serial(() => this.readFresh());
    this.data = data;
    return data;
  }

  /** Whether the grant existed. */
  async removeGrant(id: string): Promise<boolean> {
    let removed = false;
    await this.mutate((data) => {
      const before = data.grants.length;
      data.grants = data.grants.filter((g) => g.id !== id);
      removed = data.grants.length < before;
      return removed;
    });
    return removed;
  }

  /** Adds the assignment; the same one twice changes nothing. */
  async assignRole(subjectId: string, assignment: RoleAssignment): Promise<void> {
    await this.mutate((data) => {
      const list = (data.roles[subjectId] ??= []);
      if (list.some((a) => sameAssignment(a, assignment))) return false;
      list.push(structuredClone(assignment));
    });
  }

  /** Whether the assignment existed. A subject left with no assignment is dropped from the file. */
  async revokeRole(subjectId: string, assignment: RoleAssignment): Promise<boolean> {
    let removed = false;
    await this.mutate((data) => {
      const list = data.roles[subjectId] ?? [];
      const kept = list.filter((a) => !sameAssignment(a, assignment));
      removed = kept.length < list.length;
      if (kept.length === 0) delete data.roles[subjectId];
      else data.roles[subjectId] = kept;
      return removed;
    });
    return removed;
  }

  /** Replaces every assignment of the subject; an empty list drops it. */
  async setRoles(subjectId: string, assignments: RoleAssignment[]): Promise<void> {
    await this.mutate((data) => {
      if (assignments.length === 0) delete data.roles[subjectId];
      else data.roles[subjectId] = structuredClone(assignments);
    });
  }

  /**
   * Runs the engine's `apply` over the grants the file holds right now and, when the change is accepted, persists
   * the result in the same locked write. A refusal writes nothing and comes back as the engine returned it.
   * `mutation.subject` of a role change gets the stored assignments when it carries none.
   */
  async apply(governance: Governance, input: ApplyMutation): Promise<ApplyResult> {
    return this.serial(async () => {
      const release = await this.lock();
      try {
        const data = await this.readFresh(true);
        const mutation = this.withStoredRoles(data, input.mutation);
        const result = governance.apply({ ...input, mutation, current: structuredClone(data.grants) });
        if (!result.ok) {
          this.data = data;
          return result;
        }
        if (result.grants) data.grants = result.grants;
        if (result.subject?.id !== undefined) {
          const roles = result.subject.roles ?? [];
          if (roles.length === 0) delete data.roles[result.subject.id];
          else data.roles[result.subject.id] = roles;
        }
        await this.write(data);
        this.commit(data);
        return result;
      } finally {
        await release();
      }
    });
  }

  private withStoredRoles(data: StoreData, mutation: ApplyInput['mutation']): ApplyInput['mutation'] {
    const change = 'assign_role' in mutation ? mutation.assign_role : 'revoke_role' in mutation ? mutation.revoke_role : undefined;
    const id = change?.subject.id;
    if (!change || id === undefined || change.subject.roles !== undefined) return mutation;
    const subject = { ...change.subject, roles: structuredClone(data.roles[id] ?? []) };
    return 'assign_role' in mutation
      ? { assign_role: { ...mutation.assign_role, subject } }
      : { revoke_role: { ...(mutation as { revoke_role: { subject: Subject; role: RoleAssignment } }).revoke_role, subject } };
  }

  private loaded(): StoreData {
    if (!this.data) throw new Error('JsonFileStore: call load() before reading');
    return this.data;
  }

  private serial<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async mutate(change: (data: StoreData) => boolean | void): Promise<void> {
    await this.serial(async () => {
      const release = await this.lock();
      try {
        const data = await this.readFresh(true);
        if (change(data) === false) {
          this.data = data;
          return;
        }
        await this.write(data);
        this.commit(data);
      } finally {
        await release();
      }
    });
  }

  private commit(data: StoreData): void {
    this.data = data;
    for (const listener of [...this.listeners]) listener(this.snapshot());
  }

  private async readFresh(lockHeld = false): Promise<StoreData> {
    let text: string;
    try {
      text = await readFile(this.path, 'utf8');
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code !== 'ENOENT') throw cause;
      if (!this.options.createIfMissing) {
        throw new JsonStoreError('STORE_NOT_FOUND', `${this.path} does not exist; pass createIfMissing to start a new store`, { cause });
      }
      const created: StoreData = { version: STORE_VERSION, grants: [], roles: {} };
      const release = lockHeld ? undefined : await this.lock();
      try {
        if (existsSync(this.path)) return parse(this.path, await readFile(this.path, 'utf8'));
        await this.write(created);
      } finally {
        await release?.();
      }
      return created;
    }
    return parse(this.path, text);
  }

  private async write(data: StoreData): Promise<void> {
    const temp = `${this.path}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    const mode = await stat(this.path).then((s) => s.mode & 0o777, () => 0o600);
    try {
      const handle = await open(temp, 'wx', mode);
      try {
        await handle.writeFile(`${JSON.stringify(data, null, 2)}\n`);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await this.options.beforeRename?.();
      await rename(temp, this.path);
    } catch (error) {
      await unlink(temp).catch(() => undefined);
      throw error;
    }
    this.syncDirectory();
  }

  private syncDirectory(): void {
    try {
      const fd = openSync(dirname(this.path), 'r');
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    } catch {
      // Windows cannot open a directory; the rename is still atomic there.
    }
  }

  private async lock(): Promise<() => Promise<void>> {
    const token = `${process.pid}:${hostname()}:${randomBytes(8).toString('hex')}`;
    const deadline = Date.now() + this.options.lockTimeoutMs;
    for (;;) {
      try {
        await writeFile(this.lockPath, token, { flag: 'wx' });
        return async () => {
          const held = await readFile(this.lockPath, 'utf8').catch(() => undefined);
          if (held === token) await unlink(this.lockPath).catch(() => undefined);
        };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
      if (await this.takeOverStale()) continue;
      if (Date.now() >= deadline) {
        throw new JsonStoreError('STORE_LOCK_TIMEOUT', `${this.lockPath} stayed locked for ${this.options.lockTimeoutMs} ms`);
      }
      await wait(15 + Math.floor(Math.random() * 20));
    }
  }

  // A lock is stale when its owner is a dead process on this host, or when it is older than `lockStaleMs`.
  // The content is re-read right before the unlink so a lock another process just took is not removed.
  private async takeOverStale(): Promise<boolean> {
    let content: string;
    let mtimeMs: number;
    try {
      content = await readFile(this.lockPath, 'utf8');
      mtimeMs = (await stat(this.lockPath)).mtimeMs;
    } catch {
      return true;
    }
    const [pid, host] = content.split(':');
    const ownerDead = host === hostname() && Number(pid) > 0 && !processAlive(Number(pid));
    if (!ownerDead && Date.now() - mtimeMs < this.options.lockStaleMs) return false;
    if ((await readFile(this.lockPath, 'utf8').catch(() => undefined)) !== content) return true;
    await unlink(this.lockPath).catch(() => undefined);
    return true;
  }
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** Opens the store: `new JsonFileStore(options).load()`. */
export function openJsonStore(options: JsonFileStoreOptions): Promise<JsonFileStore> {
  return new JsonFileStore(options).load();
}
