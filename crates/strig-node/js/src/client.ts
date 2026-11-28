// Cliente de tempo real: recebe as capacidades do servidor por SSE ou WebSocket e decide localmente
// com o mesmo motor do servidor. Roda no navegador, no Node (>= 22 para WebSocket global) e no Bun.
import type { CapabilitySet, Context, Decision, Engine, FieldSet, PermissionArg, Strig } from './index.js';
import { parseRevision, readSse, resourceWithin, revisionReached, scopeToString, sameAnchor } from './protocol.js';
import type { Change, Resource, ServerMessage } from './protocol.js';

const sameScope = (a: Resource, b: Resource): boolean =>
  a.path.length === b.path.length && a.path.every((x, i) => sameAnchor(x, b.path[i]!));

export interface PermissionClientOptions {
  /** endpoint SSE ou WebSocket */
  url: string | URL;
  transport?: 'sse' | 'websocket';
  scopes?: Resource[];
  /** resultado de `load()` */
  strig: Pick<Strig, 'Context'>;
  /** motor montado com a mesma spec do servidor */
  engine: Engine<string>;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
  WebSocket?: typeof WebSocket;
  reconnectMinMs?: number;
  reconnectMaxMs?: number;
  /**
   * Read-your-writes: decide only from capabilities computed at this revision (`scope@value`) or
   * later. Until they are, every decision is a deny (fail closed). Raise it with `requireRevision`.
   */
  minRevision?: string;
}

type HelloMessage = Extract<ServerMessage, { type: 'hello' }>;
type CapabilitiesMessage = Extract<ServerMessage, { type: 'capabilities' }>;

interface EventPayloads {
  open: HelloMessage;
  capabilities: CapabilitiesMessage;
  change: Change;
  resync: unknown;
  revision: undefined;
  error: Error;
  disconnect: undefined;
  close: undefined;
}

type EventType = keyof EventPayloads;
type Listener = (payload: never) => void;

interface Entry {
  scope: Resource;
  set: CapabilitySet;
  context: Context;
  revision?: string;
}

export class PermissionClient<P extends string = string> {
  readonly url: string | URL;
  readonly transport: 'sse' | 'websocket';
  scopes: Resource[];
  readonly strig: Pick<Strig, 'Context'>;
  readonly engine: Engine<string>;
  readonly headers: Record<string, string>;
  readonly fetch: typeof fetch;
  readonly WebSocket: typeof WebSocket;
  readonly minDelay: number;
  readonly maxDelay: number;
  private entries = new Map<string, Entry>();
  private listeners = new Map<EventType, Set<Listener>>();
  private required?: string;
  private closed = true;
  private abort?: AbortController;
  private socket?: WebSocket;

  constructor(options: PermissionClientOptions) {
    this.url = options.url;
    this.transport = options.transport ?? 'sse';
    this.scopes = [...(options.scopes ?? [])];
    this.strig = options.strig;
    this.engine = options.engine;
    this.headers = options.headers ?? {};
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.WebSocket = options.WebSocket ?? globalThis.WebSocket;
    this.minDelay = options.reconnectMinMs ?? 500;
    this.maxDelay = options.reconnectMaxMs ?? 10_000;
    this.required = options.minRevision;
  }

  on(type: 'open', listener: (message: HelloMessage) => void): () => void;
  on(type: 'capabilities', listener: (message: CapabilitiesMessage) => void): () => void;
  on(type: 'change', listener: (change: Change) => void): () => void;
  on(type: 'resync' | 'revision' | 'disconnect' | 'close', listener: () => void): () => void;
  on(type: 'error', listener: (error: Error) => void): () => void;
  on(type: EventType, listener: Listener): () => void {
    let set = this.listeners.get(type);
    if (!set) this.listeners.set(type, (set = new Set()));
    set.add(listener);
    return () => this.listeners.get(type)?.delete(listener);
  }

  private emit<T extends EventType>(type: T, payload: EventPayloads[T]): void {
    for (const listener of this.listeners.get(type) ?? []) (listener as (payload: EventPayloads[T]) => void)(payload);
  }

  connect(): this {
    if (!this.closed) return this;
    this.closed = false;
    void this.loop();
    return this;
  }

  close(): void {
    this.closed = true;
    this.abort?.abort();
    this.socket?.close();
  }

  watch(scopes: Resource[]): void {
    const fresh = scopes.filter((s) => !this.scopes.some((t) => sameScope(s, t)));
    if (!fresh.length) return;
    this.scopes.push(...fresh);
    this.resubscribe({ type: 'watch', scopes: fresh });
  }

  unwatch(scopes: Resource[]): void {
    this.scopes = this.scopes.filter((s) => !scopes.some((t) => sameScope(s, t)));
    for (const scope of scopes) this.entries.delete(scopeToString(scope));
    this.resubscribe({ type: 'unwatch', scopes });
  }

  private resubscribe(message: { type: 'watch' | 'unwatch'; scopes: Resource[] }): void {
    if (this.closed) return;
    if (this.transport === 'websocket' && this.socket?.readyState === 1) this.socket.send(JSON.stringify(message));
    else if (this.transport === 'sse') this.abort?.abort();
  }

  /** The revision decisions must reach, when one is required. */
  get minRevision(): string | undefined {
    return this.required;
  }

  /**
   * Requires capabilities at `revision` or later (a write's revision, `scope@value`) and asks the
   * server for them. Decisions deny until they arrive; a lower revision than the current one is kept out.
   */
  requireRevision(revision: string): void {
    const current = this.required === undefined ? undefined : parseRevision(this.required);
    const next = parseRevision(revision);
    if (!next) throw new Error('revision must look like scope@value');
    if (current && current.scope === next.scope && current.value >= next.value) return;
    this.required = revision;
    this.emit('revision', undefined);
    const message = JSON.stringify({ type: 'refresh_at_least', revision });
    if (this.closed) return;
    if (this.transport === 'websocket' && this.socket?.readyState === 1) this.socket.send(message);
    else if (this.transport === 'sse') this.abort?.abort();
  }

  /** The revision the capabilities of `scope` were computed from, when the server sent one. */
  revision(scope: Resource): string | undefined {
    return this.entries.get(scopeToString(scope))?.revision;
  }

  /** `true` while a required revision is set and the capabilities that cover `resource` have not reached it. */
  behind(resource?: Resource): boolean {
    if (this.required === undefined) return false;
    const entries = [...this.entries.values()].filter((e) => resource === undefined || resourceWithin(resource, e.scope));
    return entries.length === 0 || entries.some((e) => revisionReached(this.required!, e.revision) !== 'yes');
  }

  capabilities(scope: Resource): CapabilitySet | undefined {
    return this.entries.get(scopeToString(scope))?.set;
  }

  /** Decisão local. Sem capacidades de um escopo que contenha o recurso, nega. Com `field`, decide só esse campo. */
  decide(permission: PermissionArg<P>, resource: Resource, field?: string): Decision {
    const entry = [...this.entries.values()].find((e) => resourceWithin(resource, e.scope));
    if (!entry) return { effect: 'deny', reason: { kind: 'no_applicable_grant' }, warnings: ['sem capacidades para o escopo'] };
    if (this.required !== undefined) {
      const reached = revisionReached(this.required, entry.revision);
      if (reached !== 'yes') {
        return { effect: 'deny', reason: { kind: 'no_applicable_grant' }, warnings: [`revision_${reached === 'behind' ? 'not_reached' : reached === 'other_scope' ? 'scope_mismatch' : 'untracked'}`] };
      }
    }
    const request = { subject: entry.set.subject, permission, resource };
    return this.engine.decide(entry.context, field === undefined ? request : { ...request, field });
  }

  can(permission: PermissionArg<P>, resource: Resource, field?: string): boolean {
    return this.decide(permission, resource, field).effect === 'allow';
  }

  /**
   * Os campos que o sujeito pode usar, decididos localmente com as capacidades recebidas (que
   * carregam os campos dos grants). Sem capacidades de um escopo que contenha o recurso, nenhum.
   */
  allowedFields(permission: PermissionArg<P>, resource: Resource): FieldSet {
    const entry = [...this.entries.values()].find((e) => resourceWithin(resource, e.scope));
    if (!entry) return { kind: 'none' };
    if (this.required !== undefined && revisionReached(this.required, entry.revision) !== 'yes') return { kind: 'none' };
    return this.engine.allowedFields(entry.context, { subject: entry.set.subject, permission, resource });
  }

  private handle(message: ServerMessage): void {
    switch (message.type) {
      case 'hello':
        return this.emit('open', message);
      case 'capabilities': {
        const context = new this.strig.Context();
        const set = message.set as CapabilitySet;
        context.loadCapabilities(set);
        this.entries.set(scopeToString(message.scope), { scope: message.scope, set, context, revision: message.revision });
        return this.emit('capabilities', message);
      }
      case 'change':
        return this.emit('change', message.change);
      case 'resync':
        this.entries.clear();
        return this.emit('resync', message);
      case 'error':
        return this.emit('error', new Error(message.message));
      default:
        return undefined;
    }
  }

  private async loop(): Promise<void> {
    let delay = this.minDelay;
    while (!this.closed) {
      const started = Date.now();
      try {
        if (this.transport === 'websocket') await this.runWebSocket();
        else await this.runSse();
      } catch (error) {
        if (!this.closed && (error as Error | undefined)?.name !== 'AbortError') this.emit('error', error as Error);
      }
      if (this.closed) break;
      this.emit('disconnect', undefined);
      if (Date.now() - started > this.maxDelay) delay = this.minDelay;
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, this.maxDelay);
    }
    this.emit('close', undefined);
  }

  private async runSse(): Promise<void> {
    const url = new URL(this.url, globalThis.location?.href);
    for (const scope of this.scopes) url.searchParams.append('scope', scopeToString(scope));
    if (this.required !== undefined) url.searchParams.set('min_revision', this.required);
    this.abort = new AbortController();
    const response = await this.fetch(url, {
      headers: { accept: 'text/event-stream', ...this.headers },
      signal: this.abort.signal,
    });
    if (!response.ok || !response.body) throw new Error(`SSE respondeu ${response.status}`);
    await readSse(response.body, (message) => this.handle(message));
  }

  private runWebSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = new this.WebSocket(String(this.url));
      this.socket = socket;
      socket.onopen = () => {
        if (this.scopes.length) socket.send(JSON.stringify({ type: 'watch', scopes: this.scopes }));
        if (this.required !== undefined) socket.send(JSON.stringify({ type: 'refresh_at_least', revision: this.required }));
      };
      socket.onmessage = (event) => this.handle(JSON.parse(typeof event.data === 'string' ? event.data : String(event.data)) as ServerMessage);
      socket.onerror = (event) => reject((event as ErrorEvent | undefined)?.error ?? new Error('erro no WebSocket'));
      socket.onclose = () => resolve();
    });
  }
}
