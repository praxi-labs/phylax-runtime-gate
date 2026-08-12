export type GateDecision = 'allow' | 'warn' | 'block'

export type FailMode = 'closed' | 'open'

export interface GateResult {
  decision: GateDecision
  reason: string
  riskScore?: number | undefined
  policies?: string[] | undefined
  artifact?: string | undefined
  attestationId?: string | undefined
  timestamp: string
  cached: boolean
  degraded: boolean
}

export interface CheckInput {
  tool: string | { name?: string; artifact?: string; [key: string]: unknown }
  input?: unknown
  artifact?: string | undefined
  policy?: string | undefined
  failMode?: FailMode | undefined
  signal?: AbortSignal | undefined
}

export interface RuntimeGateOptions {
  apiKey: string
  baseUrl?: string | undefined
  policy?: string | undefined
  failMode?: FailMode | undefined
  /**
   * What to do with an artifact the network has never evaluated.
   *
   * The API answers ALLOW with `coverage: "none"` for anything uncovered,
   * because a 404 would break a batch call and warning on everything unseen
   * trains people to ignore warnings. That is the right transport answer and
   * the wrong security answer for an organization that wants to run only what
   * has been evaluated. Defaults to `allow`; set `block` to fail closed.
   */
  unknownAs?: GateDecision | undefined
  allowCacheTtlMs?: number | undefined
  denyCacheTtlMs?: number | undefined
  cacheMaxEntries?: number | undefined
  timeoutMs?: number | undefined
  onDecision?: ((result: GateResult) => void) | undefined
  fetch?: typeof globalThis.fetch | undefined
}

export class GateBlockedError extends Error {
  readonly result: GateResult

  constructor(result: GateResult) {
    super(`Blocked by policy: ${result.reason}`)
    this.name = 'GateBlockedError'
    this.result = result
  }
}
