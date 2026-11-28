// Lado servidor em Node e Bun: hub de mudanças, sessões SSE/WebSocket e transportes Redis/Postgres.
// Fala o mesmo protocolo do crate strig-sync, então instâncias em Rust e em JS trocam mudanças
// pelo mesmo canal.
import type { ServerResponse } from 'node:http';
import type { CapabilitySet, Context as ContextClass, Engine, Grant, Subject } from './index.js';
import { changeAffects, encodeSse, PROTOCOL_VERSION, revisionReached, sameAnchor } from './protocol.js';
import type { Anchor, Change, ChangeKind, ClientMessage, Resource, ServerMessage } from './protocol.js';

export interface Transport {
  publish(change: Change): Promise<void>;
  /** Devolve a função que cancela a assinatura. `onReset` avisa que mudanças podem ter se perdido. */
  subscribe(onChange: (change: Change) => void, onReset?: () => void): Promise<() => Promise<unknown> | unknown>;
}

export type Provider = (subject: Subject, scope: Resource) => Promise<CapabilitySet>;

export interface SessionOptions {
  hub: Hub;
  subject: Subject;
  scopes?: Resource[];
  provider?: Provider;
  heartbeatMs?: number;
  /**
   * The revision (`scope@value`) of the data this instance has loaded, for read-your-writes. Without
   * it the session cannot prove a revision, so a `refresh_at_least` is answered with `revision_untracked`.
   */
  revision?: (scope: Resource) => Promise<string | undefined> | string | undefined;
  /** A revision the session must reach before it sends any capabilities (the `min_revision` the client asked for). */
  minRevision?: string;
}

export interface Session {
  ready: Promise<void>;
  handle(message: string | ClientMessage): Promise<void>;
  close(): void;
}

const GLOBAL_ANCHOR: Anchor = { kind: 'global' };

export function change(kind: ChangeKind, scope: Anchor, extra: Partial<Change> = {}): Change {
  return { kind, scope, origin: '', seq: 0, at: 0, ...extra };
}

export class Hub {
  readonly origin: string;
  private readonly transport: Transport | undefined;
  private seq = 0;
  private readonly listeners = new Set<(change: Change) => void>();
  private stopRelay: (() => Promise<unknown> | unknown) | undefined;

  constructor(options: { origin?: string; transport?: Transport } = {}) {
    this.origin = options.origin ?? Math.random().toString(16).slice(2).padEnd(16, '0').slice(0, 16);
    this.transport = options.transport;
  }

  subscribe(listener: (change: Change) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  deliver(item: Change): void {
    for (const listener of [...this.listeners]) {
      try {
        listener(item);
      } catch {
        // um assinante com defeito não derruba os outros
      }
    }
  }

  async publish(item: Change): Promise<Change> {
    const stamped = { ...item, origin: this.origin, seq: ++this.seq, at: item.at || Date.now() };
    this.deliver(stamped);
    if (this.transport) await this.transport.publish(stamped);
    return stamped;
  }

  /** Traz as mudanças das outras instâncias. Reconexão do transporte vira `resync`. */
  async startRelay(): Promise<void> {
    if (!this.transport || this.stopRelay) return;
    this.stopRelay = await this.transport.subscribe(
      (item) => {
        if (item.origin !== this.origin) this.deliver(item);
      },
      () => this.deliver(change('resync', GLOBAL_ANCHOR, { at: Date.now() })),
    );
  }

  async close(): Promise<void> {
    await this.stopRelay?.();
    this.stopRelay = undefined;
  }
}

const sameScope = (a: Resource, b: Resource): boolean =>
  a.path.length === b.path.length && a.path.every((x, i) => sameAnchor(x, b.path[i]!));

/**
 * Sessão de um cliente. `send` recebe cada mensagem do servidor (objeto). Para WebSocket, repasse
 * o texto recebido em `handle`.
 */
export function openSession({
  hub,
  subject,
  scopes = [],
  provider,
  heartbeatMs = 25_000,
  revision,
  minRevision,
  send,
}: SessionOptions & { send: (message: ServerMessage) => void }): Session {
  const watched = [...scopes];
  let closed = false;
  let pending: Change[] = [];
  let scheduled = false;

  let required = minRevision;

  const push = async (scope: Resource): Promise<void> => {
    if (!provider || closed) return;
    try {
      const have = await revision?.(scope);
      if (required !== undefined) {
        const reached = revisionReached(required, have);
        if (reached !== 'yes') {
          send({ type: 'error', message: reached === 'behind' ? 'revision_not_reached' : reached === 'other_scope' ? 'revision_scope_mismatch' : 'revision_untracked' });
          return;
        }
      }
      const set = await provider(subject, scope);
      send(have === undefined ? { type: 'capabilities', scope, set } : { type: 'capabilities', scope, set, revision: have });
    } catch (error) {
      send({ type: 'error', message: String((error as Error | undefined)?.message ?? error) });
    }
  };
  const pushAll = async (): Promise<void> => {
    for (const scope of watched) await push(scope);
  };

  const flush = async (): Promise<void> => {
    scheduled = false;
    const batch = pending;
    pending = [];
    if (batch.some((c) => c.kind === 'resync')) {
      send({ type: 'resync' });
      return pushAll();
    }
    const affected = new Set<Resource>();
    for (const item of batch) {
      const hits = watched.filter((scope) => changeAffects(item, subject.id ?? null, scope));
      if (!hits.length) continue;
      hits.forEach((scope) => affected.add(scope));
      send({ type: 'change', change: item });
    }
    for (const scope of affected) await push(scope);
  };

  const unsubscribe = hub.subscribe((item) => {
    pending.push(item);
    if (!scheduled) {
      scheduled = true;
      queueMicrotask(flush);
    }
  });
  const timer = heartbeatMs ? setInterval(() => send({ type: 'ping' }), heartbeatMs) : undefined;
  (timer as { unref?: () => void } | undefined)?.unref?.();

  send({ type: 'hello', origin: hub.origin, subject: subject.id, version: PROTOCOL_VERSION });
  const ready = pushAll();

  return {
    ready,
    async handle(input) {
      const message: ClientMessage = typeof input === 'string' ? (JSON.parse(input) as ClientMessage) : input;
      if (message.type === 'watch') {
        for (const scope of message.scopes) {
          if (watched.some((s) => sameScope(s, scope))) continue;
          watched.push(scope);
          await push(scope);
        }
      } else if (message.type === 'unwatch') {
        for (const scope of message.scopes) {
          const at = watched.findIndex((s) => sameScope(s, scope));
          if (at >= 0) watched.splice(at, 1);
        }
      } else if (message.type === 'refresh') {
        await pushAll();
      } else if (message.type === 'refresh_at_least') {
        required = message.revision;
        await pushAll();
      }
    },
    close() {
      closed = true;
      unsubscribe();
      if (timer) clearInterval(timer);
    },
  };
}

const SSE_HEADERS = {
  'content-type': 'text/event-stream',
  'cache-control': 'no-cache',
  connection: 'keep-alive',
};

/** `Response` de SSE (Bun.serve, Deno, Hono, qualquer runtime com Fetch API). */
export function sseResponse(options: SessionOptions): Response {
  const encoder = new TextEncoder();
  let session: Session | undefined;
  const body = new ReadableStream({
    start(controller) {
      session = openSession({
        ...options,
        send: (message) => {
          try {
            controller.enqueue(encoder.encode(encodeSse(message)));
          } catch {
            session?.close();
          }
        },
      });
    },
    cancel() {
      session?.close();
    },
  });
  return new Response(body, { headers: SSE_HEADERS });
}

/** SSE sobre `http.ServerResponse` do Node. */
export function pipeSse(res: ServerResponse, options: SessionOptions): Session {
  res.writeHead(200, SSE_HEADERS);
  const session = openSession({ ...options, send: (message) => res.write(encodeSse(message)) });
  res.on('close', () => session.close());
  return session;
}

/** Provider padrão: carrega os grants e filtra com `engine.capabilities`, como o `EngineProvider` do Rust. */
export function engineProvider({
  engine,
  Context,
  loadGrants,
}: {
  engine: Engine;
  Context: typeof ContextClass;
  loadGrants: (subject: Subject, scope: Resource) => Promise<Grant[]> | Grant[];
}): Provider {
  return async (subject, scope) => {
    const context = new Context({ grants: await loadGrants(subject, scope) });
    return engine.capabilities(context, subject, scope);
  };
}

/** Transporte em memória: hubs que recebem o mesmo objeto trocam mudanças. */
export function memoryTransport(): Transport {
  const subscribers = new Set<(change: Change) => void>();
  return {
    async publish(item) {
      for (const fn of subscribers) queueMicrotask(() => fn(item));
    },
    async subscribe(onChange) {
      subscribers.add(onChange);
      return async () => subscribers.delete(onChange);
    },
  };
}

const parse = (text: string): Change | undefined => {
  try {
    return JSON.parse(text) as Change;
  } catch {
    return undefined;
  }
};

/** `redis` (node-redis v4+) e `RedisClient` do Bun: `publish(canal, texto)` e `subscribe(canal, (texto) => ...)`. */
export interface RedisPublisher {
  publish(channel: string, message: string): unknown;
}

export interface RedisSubscriber {
  subscribe(channel: string, listener: (message: string) => void): unknown;
  unsubscribe(channel: string): unknown;
  on?(event: 'reconnecting' | 'ready', listener: () => void): unknown;
  off?(event: 'reconnecting' | 'ready', listener: () => void): unknown;
}

/**
 * Redis pub/sub. Serve para o `redis` (node-redis v4+) e para o `RedisClient` nativo do Bun, que
 * têm a mesma assinatura: `publish(canal, texto)` e `subscribe(canal, (texto) => ...)`. O assinante
 * precisa de uma conexão só dele.
 */
export function redisTransport({
  publisher,
  subscriber,
  channel = 'strig:changes',
}: {
  publisher: RedisPublisher;
  subscriber: RedisSubscriber;
  channel?: string;
}): Transport {
  return {
    async publish(item) {
      await publisher.publish(channel, JSON.stringify(item));
    },
    async subscribe(onChange, onReset) {
      let dropped = false;
      const onDrop = (): void => {
        dropped = true;
      };
      const onReady = (): void => {
        if (dropped) onReset?.();
        dropped = false;
      };
      subscriber.on?.('reconnecting', onDrop);
      subscriber.on?.('ready', onReady);
      await subscriber.subscribe(channel, (text) => {
        const item = parse(text);
        if (item) onChange(item);
      });
      return async () => {
        subscriber.off?.('reconnecting', onDrop);
        subscriber.off?.('ready', onReady);
        await subscriber.unsubscribe(channel);
      };
    },
  };
}

export interface IoredisSubscriber {
  subscribe(channel: string): unknown;
  unsubscribe(channel: string): unknown;
  on(event: 'message', listener: (channel: string, message: string) => void): unknown;
  on(event: 'reconnecting', listener: () => void): unknown;
  off(event: 'message', listener: (channel: string, message: string) => void): unknown;
  off(event: 'reconnecting', listener: () => void): unknown;
}

/** ioredis: `subscribe(canal)` e evento `message`. */
export function ioredisTransport({
  publisher,
  subscriber,
  channel = 'strig:changes',
}: {
  publisher: RedisPublisher;
  subscriber: IoredisSubscriber;
  channel?: string;
}): Transport {
  return {
    async publish(item) {
      await publisher.publish(channel, JSON.stringify(item));
    },
    async subscribe(onChange, onReset) {
      const onMessage = (from: string, text: string): void => {
        if (from !== channel) return;
        const item = parse(text);
        if (item) onChange(item);
      };
      const onReconnect = (): void => onReset?.();
      subscriber.on('message', onMessage);
      subscriber.on('reconnecting', onReconnect);
      await subscriber.subscribe(channel);
      return async () => {
        subscriber.off('message', onMessage);
        subscriber.off('reconnecting', onReconnect);
        await subscriber.unsubscribe(channel);
      };
    },
  };
}

/** O que `notify` precisa: `Pool`, `Client` ou a transação do `pg`. */
export interface Queryable {
  query(sql: string, params?: unknown[]): Promise<unknown>;
}

export interface PgListener extends Queryable {
  on(event: 'notification', listener: (message: { channel: string; payload?: string | undefined }) => void): unknown;
  on(event: 'end', listener: () => void): unknown;
  off(event: 'notification', listener: (message: { channel: string; payload?: string | undefined }) => void): unknown;
  off(event: 'end', listener: () => void): unknown;
}

/**
 * Postgres LISTEN/NOTIFY com o pacote `pg`. `client` publica (Pool ou Client); `listener` é um
 * `Client` conectado e dedicado. Para avisar dentro da transação que grava o grant, chame
 * `notify(tx, canal, mudança)` antes do COMMIT: o aviso só sai se a transação gravar.
 */
export function pgTransport({
  client,
  listener,
  channel = 'strig_changes',
}: {
  client: Queryable;
  listener: PgListener;
  channel?: string;
}): Transport {
  const quoted = `"${channel.replaceAll('"', '""')}"`;
  return {
    async publish(item) {
      await notify(client, channel, item);
    },
    async subscribe(onChange, onReset) {
      const onNotification = (message: { channel: string; payload?: string | undefined }): void => {
        if (message.channel !== channel) return;
        const item = parse(message.payload ?? '');
        if (item) onChange(item);
      };
      const onEnd = (): void => onReset?.();
      listener.on('notification', onNotification);
      listener.on('end', onEnd);
      await listener.query(`LISTEN ${quoted}`);
      return async () => {
        listener.off('notification', onNotification);
        listener.off('end', onEnd);
        await listener.query(`UNLISTEN ${quoted}`).catch(() => {});
      };
    },
  };
}

export async function notify(queryable: Queryable, channel: string, item: Change): Promise<void> {
  await queryable.query('SELECT pg_notify($1, $2)', [channel, JSON.stringify(item)]);
}
