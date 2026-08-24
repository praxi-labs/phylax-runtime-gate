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
  /**
   * The tool's own source, as relative path to contents.
   *
   * Supplying this turns the check into an analysis rather than a lookup. The
   * champions promoted for that track execute the code and return a verdict,
   * so a tool the network has never seen is judged on what it does instead of
   * falling to `unknownAs`. This is the case a runtime gate exists for: the
   * tool worth stopping is rarely one that has already been attested.
   */
  files?: Record<string, string> | undefined
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
  /**
   * Refuse to allow when only the static scanner reached an analysed tool.
   *
   * A verdict backed by champion agents and one from a regex pass are
   * indistinguishable if you read the verdict alone. A gate that cares about
   * the difference sets this; it applies to analysis, not to lookups.
   */
  requireChampions?: boolean | undefined
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
