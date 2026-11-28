// Angular bindings for the real-time PermissionClient: `provideStrig`, `StrigService`, `*strigCan` and `strigCanActivate`.
// Angular 17+ (standalone, signals). Built with ngc in partial mode so the app's linker can finish it.
// @angular/core is a static import on purpose (see README).
import {
  computed,
  DestroyRef,
  Directive,
  effect,
  inject,
  Injectable,
  Injector,
  InjectionToken,
  Input,
  isSignal,
  makeEnvironmentProviders,
  PLATFORM_ID,
  runInInjectionContext,
  signal,
  TemplateRef,
  ViewContainerRef,
} from '@angular/core';
import type { EmbeddedViewRef, EnvironmentProviders, Signal } from '@angular/core';
import { isPlatformServer } from '@angular/common';
import type { PermissionClient } from './client.js';
import { bridgeFor } from './client-bridge.js';
import type { StrigStatus } from './client-bridge.js';
import type { PermissionArg } from './index.js';
import type { Resource } from './protocol.js';

export type { StrigStatus } from './client-bridge.js';

export interface StrigOptions {
  /** Open the stream while the injector lives. Default `true`; never connects on the server. */
  connect?: boolean;
}

export const STRIG_CLIENT = new InjectionToken<PermissionClient<any>>('STRIG_CLIENT');
export const STRIG_OPTIONS = new InjectionToken<StrigOptions>('STRIG_OPTIONS');

type Reactive<T> = T | Signal<T>;
const read = <T>(value: Reactive<T>): T => (isSignal(value) ? (value as Signal<T>)() : value);

/** Registers the client and `StrigService`: `provideStrig(client)` in `bootstrapApplication` or in a route's `providers`. */
export function provideStrig<P extends string>(client: PermissionClient<P>, options: StrigOptions = {}): EnvironmentProviders {
  return makeEnvironmentProviders([
    { provide: STRIG_CLIENT, useValue: client },
    { provide: STRIG_OPTIONS, useValue: options },
    StrigService,
  ]);
}

@Injectable()
export class StrigService<P extends string = string> {
  private readonly bridge = bridgeFor(inject(STRIG_CLIENT) as PermissionClient<P>);
  private readonly server = isPlatformServer(inject(PLATFORM_ID));
  private readonly tick = signal(this.bridge.getVersion());
  private readonly state = signal<StrigStatus>(this.bridge.getStatus());

  /** Connection state: `connected`, `resyncing`, `behind` (a required revision not reached yet) and the last `error`. */
  readonly status: Signal<StrigStatus> = this.state.asReadonly();

  constructor() {
    const destroyRef = inject(DestroyRef);
    const unsubscribe = this.bridge.subscribe(() => {
      this.state.set(this.bridge.getStatus());
      this.tick.set(this.bridge.getVersion());
    });
    const release = !this.server && (inject(STRIG_OPTIONS, { optional: true })?.connect ?? true) ? this.bridge.retain() : undefined;
    destroyRef.onDestroy(() => {
      unsubscribe();
      release?.();
    });
  }

  /**
   * `true` only with an open stream, received capabilities and an allow. Updates when capabilities change.
   * Arguments may be signals. Denies on the server.
   */
  can(permission: Reactive<PermissionArg<P> | null | undefined>, resource: Reactive<Resource | null | undefined>): Signal<boolean> {
    return computed(() => {
      this.tick();
      const p = read(permission);
      const r = read(resource);
      if (this.server || !p || !r) return false;
      return this.bridge.can(p, r);
    });
  }

  /** Resolves `true` once capabilities arrived, `false` after `timeoutMs` (default 5000). */
  settled(timeoutMs = 5000): Promise<boolean> {
    return this.bridge.settled(timeoutMs);
  }

  /** Read your own writes: deny until the capabilities reach `revision` (the revision a write returned). */
  requireRevision(revision: string): void {
    if (!this.server) this.bridge.requireRevision(revision);
  }

  /** One-shot decision at call time. */
  check(permission: PermissionArg<P>, resource: Resource): boolean {
    return !this.server && this.bridge.can(permission, resource);
  }
}

/** `*strigCan="'document.view'; resource: r; else denied"`. Shows the template on an allow, the `else` template otherwise. */
@Directive({ selector: '[strigCan]', standalone: true })
export class StrigCanDirective<P extends string = string> {
  private readonly template = inject<TemplateRef<unknown>>(TemplateRef);
  private readonly container = inject(ViewContainerRef);
  private readonly permission = signal<PermissionArg<P> | null | undefined>(undefined);
  private readonly resource = signal<Resource | null | undefined>(undefined);
  private readonly fallback = signal<TemplateRef<unknown> | null | undefined>(undefined);
  private view?: EmbeddedViewRef<unknown>;
  private shown?: TemplateRef<unknown>;

  @Input({ required: true }) set strigCan(value: PermissionArg<P> | null | undefined) {
    this.permission.set(value);
  }
  @Input() set strigCanResource(value: Resource | null | undefined) {
    this.resource.set(value);
  }
  @Input() set strigCanElse(value: TemplateRef<unknown> | null | undefined) {
    this.fallback.set(value);
  }

  constructor() {
    const allowed = inject(StrigService<P>).can(this.permission, this.resource);
    effect(() => {
      const wanted = allowed() ? this.template : (this.fallback() ?? undefined);
      if (wanted === this.shown && (wanted === undefined || this.view)) return;
      this.container.clear();
      this.view = wanted ? this.container.createEmbeddedView(wanted) : undefined;
      this.shown = wanted;
    });
  }
}

export interface StrigGuardOptions {
  /** How long to wait for capabilities before denying. Default 5000 ms. */
  waitMs?: number;
  /** Runs in the injection context on a deny; return a `UrlTree` to redirect. Default: `false`. */
  onDeny?: (route: any, state: any) => unknown;
}

/**
 * Functional route guard: `canActivate: [strigCanActivate('document.view', (route) => ({ path: [...] }))]`.
 * Waits for capabilities (up to `waitMs`), then decides locally. Anything short of an allow denies.
 */
export function strigCanActivate<P extends string = string>(
  permission: PermissionArg<P>,
  resource: Resource | ((route: any, state: any) => Resource),
  options: StrigGuardOptions = {},
): (route: any, state: any) => Promise<any> {
  return async (route, state) => {
    const service = inject(StrigService<P>);
    const injector = inject(Injector);
    const deny = (): unknown => (options.onDeny ? runInInjectionContext(injector, () => options.onDeny!(route, state)) : false) ?? false;
    try {
      if (!(await service.settled(options.waitMs ?? 5000))) return deny();
      const target = typeof resource === 'function' ? resource(route, state) : resource;
      return service.check(permission, target) ? true : deny();
    } catch {
      return false;
    }
  };
}
