// React bindings for the real-time PermissionClient: `StrigProvider`, `useCan`, `<Can>` and `useStrigStatus`.
// React 18 and 19. React is a static import on purpose (see README): the app's bundler must resolve its own copy.
import { createContext, createElement, Fragment, useContext, useEffect, useMemo, useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';
import type { PermissionClient } from './client.js';
import { bridgeFor, DISCONNECTED } from './client-bridge.js';
import type { ClientBridge, StrigStatus } from './client-bridge.js';
import type { PermissionArg } from './index.js';
import type { Resource } from './protocol.js';

export type { StrigStatus } from './client-bridge.js';

const Context = createContext<ClientBridge<any> | undefined>(undefined);

const noopSubscribe = (): (() => void) => () => {};
const alwaysDisconnected = (): StrigStatus => DISCONNECTED;
const alwaysDenied = (): boolean => false;

export interface StrigProviderProps<P extends string = string> {
  client: PermissionClient<P>;
  /** Open the stream on mount and close it on unmount. Default `true`; never connects on the server. */
  connect?: boolean;
  children?: ReactNode;
}

/** Makes `client` available to `useCan`, `<Can>` and `useStrigStatus`. */
export function StrigProvider<P extends string = string>({ client, connect = true, children }: StrigProviderProps<P>): ReactNode {
  const bridge = useMemo(() => bridgeFor(client), [client]);
  useEffect(() => (connect ? bridge.retain() : undefined), [bridge, connect]);
  return createElement(Context.Provider, { value: bridge }, children);
}

/**
 * Re-renders when capabilities change. Denies without a provider, without a connection, without a decision and on the server.
 * Pass a stable `resource` or accept one extra read per render; the answer is a boolean, so it never loops.
 */
export function useCan<P extends string = string>(permission: PermissionArg<P>, resource: Resource): boolean {
  const bridge = useContext(Context);
  return useSyncExternalStore(
    bridge ? bridge.subscribe : noopSubscribe,
    bridge ? () => bridge.can(permission, resource) : alwaysDenied,
    alwaysDenied,
  );
}

/** Connection state: `connected`, `resyncing`, `behind` (a required revision not reached yet) and the last `error`. */
export function useStrigStatus(): StrigStatus {
  const bridge = useContext(Context);
  return useSyncExternalStore(
    bridge ? bridge.subscribe : noopSubscribe,
    bridge ? () => bridge.getStatus() : alwaysDisconnected,
    alwaysDisconnected,
  );
}

/** Returns `requireRevision(revision)`: after a write, deny until the capabilities reach the write's revision. */
export function useRequireRevision(): (revision: string) => void {
  const bridge = useContext(Context);
  return useMemo(() => (revision: string) => bridge?.requireRevision(revision), [bridge]);
}

export interface CanProps<P extends string = string> {
  permission: PermissionArg<P>;
  resource: Resource;
  /** Rendered when access is not allowed (including while there is no decision). */
  fallback?: ReactNode;
  children?: ReactNode;
}

/** Renders `children` on an allow and `fallback` otherwise. */
export function Can<P extends string = string>({ permission, resource, fallback = null, children }: CanProps<P>): ReactNode {
  const allowed = useCan<P>(permission, resource);
  return createElement(Fragment, null, allowed ? children : fallback);
}
