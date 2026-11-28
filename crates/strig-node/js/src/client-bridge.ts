// Framework-neutral state around a PermissionClient, shared by the React and Angular bindings.
// Everything here fails closed: without a connection, without capabilities or on any error the answer is "deny".
import type { PermissionClient } from './client.js';
import type { Resource } from './protocol.js';

/** Connection state of a `PermissionClient`. */
export interface StrigStatus {
  /** The stream is open and capabilities were received since it opened. */
  readonly connected: boolean;
  /** The server asked for a resync and the new capabilities have not arrived yet. */
  readonly resyncing: boolean;
  /** The last transport or server error, cleared when the stream opens again. */
  readonly error: Error | undefined;
  /** A minimum revision is required and the capabilities have not reached it: every decision denies. */
  readonly behind: boolean;
  /** The revision the required scope's capabilities were computed from, when known. */
  readonly required: string | undefined;
}

export const DISCONNECTED: StrigStatus = Object.freeze({ connected: false, resyncing: false, error: undefined, behind: false, required: undefined });

// `release()` closes on the next tick, so a release followed at once by a retain (React StrictMode) keeps one stream.
const CLOSE_DELAY_MS = 0;

export class ClientBridge<P extends string = string> {
  private status: StrigStatus = DISCONNECTED;
  private opened = false;
  private received = false;
  private version = 0;
  private readonly listeners = new Set<() => void>();
  private holders = 0;
  private closing?: ReturnType<typeof setTimeout>;

  constructor(readonly client: PermissionClient<P>) {
    client.on('open', () => {
      this.opened = true;
      this.update({ error: undefined });
    });
    client.on('capabilities', () => {
      this.opened = true;
      this.received = true;
      this.update({ error: undefined, resyncing: false });
    });
    client.on('resync', () => {
      this.received = false;
      this.update({ resyncing: true });
    });
    client.on('revision', () => this.update({}));
    client.on('error', (error) => this.update({ error }));
    client.on('disconnect', () => this.drop());
    client.on('close', () => this.drop());
  }

  private drop(): void {
    this.opened = false;
    this.received = false;
    this.update({ resyncing: false });
  }

  private update(patch: Partial<Pick<StrigStatus, 'resyncing' | 'error'>>): void {
    this.status = {
      connected: this.opened && this.received,
      resyncing: patch.resyncing ?? this.status.resyncing,
      error: 'error' in patch ? patch.error : this.status.error,
      behind: this.client.behind(),
      required: this.client.minRevision,
    };
    this.version += 1;
    for (const listener of [...this.listeners]) listener();
  }

  /** Immutable snapshot, replaced on every change. */
  getStatus(): StrigStatus {
    return this.status;
  }

  /** Counter that moves whenever a decision may have changed. */
  getVersion(): number {
    return this.version;
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  /** Asks for capabilities at `revision` or later (the revision of a write just made). Denies until they arrive. */
  requireRevision(revision: string): void {
    this.client.requireRevision(revision);
  }

  /** `true` only with an open stream, received capabilities and an allow from the local engine. */
  can(permission: string, resource: Resource): boolean {
    if (!this.status.connected) return false;
    try {
      return this.client.can(permission as never, resource);
    } catch {
      return false;
    }
  }

  /** Resolves `true` once capabilities are in, or `false` after `timeoutMs`. */
  settled(timeoutMs: number): Promise<boolean> {
    if (this.status.connected) return Promise.resolve(true);
    return new Promise((resolve) => {
      let unsubscribe = () => {};
      const timer = setTimeout(() => {
        unsubscribe();
        resolve(false);
      }, timeoutMs);
      unsubscribe = this.subscribe(() => {
        if (!this.status.connected) return;
        clearTimeout(timer);
        unsubscribe();
        resolve(true);
      });
    });
  }

  /** Opens the stream for one holder; the last `release` closes it. Never call this on the server. */
  retain(): () => void {
    this.holders += 1;
    if (this.closing !== undefined) {
      clearTimeout(this.closing);
      this.closing = undefined;
    } else if (this.holders === 1) {
      this.client.connect();
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.holders -= 1;
      if (this.holders > 0) return;
      this.closing = setTimeout(() => {
        this.closing = undefined;
        this.client.close();
      }, CLOSE_DELAY_MS);
    };
  }
}

const bridges = new WeakMap<PermissionClient<any>, ClientBridge<any>>();

/** One bridge per client, created on first use. Creating it only listens; it never connects. */
export function bridgeFor<P extends string>(client: PermissionClient<P>): ClientBridge<P> {
  let bridge = bridges.get(client) as ClientBridge<P> | undefined;
  if (!bridge) bridges.set(client, (bridge = new ClientBridge(client)));
  return bridge;
}
