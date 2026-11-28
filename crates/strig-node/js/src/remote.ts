// Client for the Strig decision server (strig-server, contract in crates/strig-server/API.md).
// Every call fails closed: a network error, a timeout, any status other than 200, an unreadable body
// or an open circuit is a deny, never an allow, and no call throws.

import type { Decision, Subject } from './index.js';
import { parseRevision, revisionReached } from './protocol.js';
import type { Resource } from './protocol.js';

/** Codes of `crates/strig-server/API.md`. A code this client does not know arrives as `{ unknown: text }`. */
export type ErrorCode =
  | 'malformed_json'
  | 'invalid_request'
  | 'batch_too_large'
  | 'too_many_resources'
  | 'not_found'
  | 'method_not_allowed'
  | 'body_too_large'
  | 'unsupported_media_type'
  | 'source_unavailable'
  | 'query_limit_exceeded'
  | 'overloaded'
  | 'relation_depth_exceeded'
  | 'deadline_exceeded'
  | 'clock_unavailable'
  | 'revision_not_reached'
  | 'revision_mismatch'
  | 'internal';

export type FailureReason = 'circuit_open' | 'timeout' | 'unreachable' | 'server' | 'rejected' | 'invalid_request' | 'invalid_response' | 'unexpected_status';

export interface Failure {
  reason: FailureReason;
  status?: number;
  code?: ErrorCode | { unknown: string };
  /** Fixed text of ours for a known code; the server's own text is never carried. */
  message?: string;
}

export interface CheckInput {
  subject: Subject;
  permission: string;
  resource: Resource;
  env?: Record<string, unknown>;
  /** Answer only from data at this revision (`scope@value`) or later; overrides `RemoteOptions.minRevision` for this check. */
  minRevision?: string;
}

export interface RemoteResult {
  /** `true` only for a `200` whose `decision.effect` is `allow`. */
  allowed: boolean;
  decision?: Decision;
  evaluatedAt?: number;
  /** The revision of the data the decision was made from, when the server tracks one. */
  revision?: string;
  failure?: Failure;
}

export interface BreakerOptions {
  /** Consecutive failures that open the circuit (default 5). */
  failureThreshold?: number;
  /** How long an open circuit refuses calls, in ms (default 30000). */
  waitMs?: number;
  /** Monotonic clock in ms; inject it in tests (default `performance.now`). */
  clock?: () => number;
}

export interface RemoteOptions {
  url: string;
  /** Per call, also sent as `x-strig-timeout-ms` (default 2000, at most 2_000_000_000). */
  timeoutMs?: number;
  fetch?: typeof fetch;
  headers?: Record<string, string>;
  breaker?: BreakerOptions;
  /** Read-your-writes for every call: the server answers only from data at this revision or later, else the call is denied. */
  minRevision?: string;
}

type Permit = { generation: number; probe: boolean };
type BreakerState = 'closed' | 'open' | 'half-open';

const KNOWN_CODES = new Set<string>([
  'malformed_json',
  'invalid_request',
  'batch_too_large',
  'too_many_resources',
  'not_found',
  'method_not_allowed',
  'body_too_large',
  'unsupported_media_type',
  'source_unavailable',
  'query_limit_exceeded',
  'overloaded',
  'relation_depth_exceeded',
  'deadline_exceeded',
  'clock_unavailable',
  'revision_not_reached',
  'revision_mismatch',
  'internal',
]);

/** Fixed texts per code, ours: the text a server sends is never echoed to the caller of the middleware. */
export const ERROR_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  source_unavailable: 'the grant source is unavailable; access is denied',
  invalid_request: 'the decision request was refused',
  deadline_exceeded: 'the decision was not ready in time; access is denied',
  revision_not_reached: 'the decision data has not reached the required revision; access is denied',
  revision_mismatch: 'the required revision belongs to another data scope; access is denied',
  overloaded: 'the decision service is overloaded; access is denied',
  internal: 'the decision could not be computed; access is denied',
});

export function messageFor(code: string): string {
  return Object.hasOwn(ERROR_MESSAGES, code) ? ERROR_MESSAGES[code]! : 'the decision could not be computed; access is denied';
}

/** A code the client knows keeps its name; any other text becomes `{ unknown: text }`, never an error. */
export function parseErrorCode(value: unknown): ErrorCode | { unknown: string } {
  if (typeof value !== 'string' || value === '') return { unknown: '' };
  return KNOWN_CODES.has(value) ? (value as ErrorCode) : { unknown: value };
}

// Timers above 2^31-1 ms fire at once; the grace keeps the sum under it.
const MAX_TIMEOUT_MS = 2_000_000_000;
// The client gives up a little after the deadline it sent, so the server's own `deadline_exceeded` can arrive first.
const TIMEOUT_GRACE_MS = 50;

const monotonic = (): number => performance.now();

/** Circuit breaker: closed, open for `waitMs`, then half-open with one probe. Each permit belongs to one generation. */
export class CircuitBreaker {
  readonly failureThreshold: number;
  readonly waitMs: number;
  readonly clock: () => number;
  state: BreakerState = 'closed';
  generation = 0;
  private failures = 0;
  private openedAt = 0;
  private probing = false;

  constructor(options: BreakerOptions = {}) {
    this.failureThreshold = positive(options.failureThreshold ?? 5, 'failureThreshold');
    this.waitMs = positive(options.waitMs ?? 30_000, 'waitMs');
    this.clock = options.clock ?? monotonic;
  }

  /** `null` when the call is refused. */
  acquire(): Permit | null {
    if (this.state === 'closed') return { generation: this.generation, probe: false };
    if (this.state === 'open') {
      if (this.clock() - this.openedAt < this.waitMs) return null;
      this.#move('half-open');
      this.probing = true;
      return { generation: this.generation, probe: true };
    }
    if (this.probing) return null;
    this.probing = true;
    return { generation: this.generation, probe: true };
  }

  /** The server answered. A permit from an older generation is ignored: a late answer never closes the circuit. */
  success(permit: { generation: number }): void {
    if (permit.generation !== this.generation) return;
    if (this.state === 'half-open') this.#move('closed');
    this.failures = 0;
  }

  /** The server answered, but said nothing about its own health (a 4xx with a valid error body): free the probe, change nothing else. */
  release(permit: { generation: number }): void {
    if (permit.generation !== this.generation) return;
    if (this.state === 'half-open') this.probing = false;
  }

  failure(permit: { generation: number }): void {
    if (permit.generation !== this.generation) return;
    if (this.state === 'half-open') return this.#open();
    this.failures += 1;
    if (this.failures >= this.failureThreshold) this.#open();
  }

  #open(): void {
    this.#move('open');
    this.openedAt = this.clock();
  }

  #move(state: BreakerState): void {
    this.state = state;
    this.generation += 1;
    this.failures = 0;
    this.probing = false;
  }
}

function positive(value: number, name: string, max = Infinity): number {
  if (!Number.isFinite(value) || value <= 0) throw new TypeError(`${name} must be a positive number`);
  if (value > max) throw new TypeError(`${name} must be at most ${max}`);
  return value;
}

interface Outcome<T> {
  body?: T;
  failure?: Failure;
  neutral?: boolean;
  cause?: unknown;
}

interface WireDecision {
  decision: Decision;
  evaluated_at?: number;
  revision?: string;
}

type ErrorBody = { error?: { code?: unknown } } | undefined;

/** Never throws on a decision: every failure is `allowed: false` with a `failure`. */
export class RemoteClient {
  private readonly base: string;
  private readonly timeoutMs: number;
  private readonly fetch: typeof fetch;
  private readonly headers: Record<string, string>;
  private readonly minRevision?: string;
  readonly breaker: CircuitBreaker;

  constructor(options: RemoteOptions) {
    if (typeof options?.url !== 'string' || options.url === '') throw new TypeError('url is required');
    this.base = options.url.replace(/\/+$/, '');
    this.timeoutMs = positive(options.timeoutMs ?? 2000, 'timeoutMs', MAX_TIMEOUT_MS);
    const fetchImpl = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (typeof fetchImpl !== 'function') throw new TypeError('no fetch available: pass options.fetch');
    this.fetch = fetchImpl;
    this.headers = options.headers ?? {};
    if (options.minRevision !== undefined) this.minRevision = checkedRevision(options.minRevision);
    this.breaker = new CircuitBreaker(options.breaker);
  }

  /**
   * One decision. `request` is `{ subject, permission, resource, env? }`.
   */
  async check(request: CheckInput): Promise<RemoteResult> {
    const { minRevision, ...rest } = request;
    const required = minRevision === undefined ? this.minRevision : checkedRevision(minRevision);
    const answer = await this.#call<WireDecision>('/v1/check', rest, (body) => (validCheck(body) ? true : null), required);
    if (answer.failure) return { allowed: false, failure: answer.failure };
    return withRevision(toResult(answer.body!), required);
  }

  /** Many decisions in one call; the answers keep the request order. A failed call denies every check with the same failure. Throws `TypeError` on a non-array: a programming error, not a decision. */
  async checkBatch(requests: CheckInput[], options: { minRevision?: string } = {}): Promise<RemoteResult[]> {
    if (!Array.isArray(requests)) throw new TypeError('requests must be an array');
    if (requests.length === 0) return [];
    const required = options.minRevision === undefined ? this.minRevision : checkedRevision(options.minRevision);
    let batchRevision: string | undefined;
    const answer = await this.#call<WireDecision[]>('/v1/check/batch', { checks: requests.map(({ minRevision: _drop, ...rest }) => rest) }, (body) => {
      const shaped = body as { results?: unknown; revision?: unknown } | undefined;
      const results = shaped?.results;
      if (typeof shaped?.revision === 'string') batchRevision = shaped.revision;
      return Array.isArray(results) && results.length === requests.length && results.every(validCheck) ? (results as WireDecision[]) : null;
    }, required);
    const failure = answer.failure;
    if (failure) return requests.map(() => ({ allowed: false, failure: { ...failure } }));
    return answer.body!.map((item) => withRevision(toResult({ ...item, revision: item.revision ?? batchRevision }), required));
  }

  async #call<T>(path: string, payload: unknown, validate: (body: unknown) => T | true | null, minRevision?: string): Promise<Outcome<T>> {
    // A payload that cannot be serialized is the caller's mistake: it never reaches the server or the breaker.
    let text: string | undefined;
    try {
      text = JSON.stringify(payload);
    } catch {
      return { failure: { reason: 'invalid_request' } };
    }
    if (typeof text !== 'string') return { failure: { reason: 'invalid_request' } };
    const permit = this.breaker.acquire();
    if (!permit) return { failure: { reason: 'circuit_open' } };
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let timedOut = false;
    // The deadline does not depend on `fetch` honouring the signal: the race settles on the timer either way.
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
        reject(new Error('timeout'));
      }, this.timeoutMs + TIMEOUT_GRACE_MS);
    });
    const sent = this.#send(path, text, controller.signal, validate, minRevision);
    sent.catch(() => {}); // a send that loses the race must not become an unhandled rejection
    let outcome: Outcome<T>;
    try {
      outcome = await Promise.race([sent, deadline]);
    } catch (error) {
      outcome = { failure: { reason: timedOut ? 'timeout' : 'unreachable' }, cause: error };
    } finally {
      clearTimeout(timer);
    }
    if (!outcome.failure) this.breaker.success(permit);
    else if (outcome.neutral) this.breaker.release(permit);
    else this.breaker.failure(permit);
    return outcome;
  }

  async #send<T>(path: string, text: string, signal: AbortSignal, validate: (body: unknown) => T | true | null, minRevision?: string): Promise<Outcome<T>> {
    const response = await this.fetch(this.base + path, {
      method: 'POST',
      // A redirect is a failure (API.md): following it would also carry the custom headers to another host.
      redirect: 'manual',
      headers: {
        ...this.headers,
        'content-type': 'application/json',
        'x-strig-timeout-ms': String(Math.max(1, Math.ceil(this.timeoutMs))),
        ...(minRevision === undefined ? {} : { 'x-strig-min-revision': minRevision }),
      },
      body: text,
      signal,
    });
    const raw = await response.text();
    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      body = undefined;
    }
    if (response.status !== 200) {
      const failure = failureOf(response.status, body as ErrorBody);
      // A 4xx with an error body from the API is the server alive and refusing the request: neutral for the circuit.
      // A 4xx without one (a gateway's 401, 404, 429) says nothing about the server and counts as a failure.
      return { failure, neutral: (failure.reason === 'rejected' && hasErrorBody(body)) || isRevisionRefusal(failure) };
    }
    const valid = body === undefined ? null : validate(body);
    if (!valid) return { failure: { reason: 'invalid_response', status: 200 } };
    return { body: valid === true ? (body as T) : valid };
  }
}

// The data is alive but behind: not a sign the server is unhealthy, so it does not open the circuit.
function isRevisionRefusal(failure: Failure): boolean {
  return failure.code === 'revision_not_reached' || failure.code === 'revision_mismatch';
}

function hasErrorBody(body: unknown): boolean {
  const code = (body as ErrorBody)?.error?.code;
  return typeof code === 'string' && code !== '';
}

function failureOf(status: number, body: ErrorBody): Failure {
  const code = body?.error?.code === undefined ? undefined : parseErrorCode(body.error.code);
  const named = typeof code === 'string' ? { code, message: messageFor(code) } : code ? { code } : {};
  if (status >= 500) return { reason: 'server', status, ...named };
  if (status >= 400) return { reason: 'rejected', status, ...named };
  return { reason: 'unexpected_status', status, ...named };
}

function validCheck(body: unknown): boolean {
  const effect = (body as { decision?: { effect?: unknown } } | undefined)?.decision?.effect;
  return effect === 'allow' || effect === 'deny';
}

function toResult(body: WireDecision): RemoteResult {
  const result: RemoteResult = { allowed: body.decision.effect === 'allow', decision: body.decision, evaluatedAt: body.evaluated_at };
  if (typeof body.revision === 'string') result.revision = body.revision;
  return result;
}

function checkedRevision(revision: string): string {
  if (typeof revision !== 'string' || parseRevision(revision) === undefined) throw new TypeError('minRevision must look like scope@value');
  return revision;
}

/** A server that ignores the requirement cannot talk the client past it: an answer that does not prove the revision is a deny. */
function withRevision(result: RemoteResult, required: string | undefined): RemoteResult {
  if (required === undefined) return result;
  const reached = revisionReached(required, result.revision);
  if (reached === 'yes') return result;
  const code = reached === 'behind' ? 'revision_not_reached' : reached === 'other_scope' ? 'revision_mismatch' : 'revision_not_reached';
  return { allowed: false, failure: { reason: 'server', code, message: messageFor(code) } };
}
