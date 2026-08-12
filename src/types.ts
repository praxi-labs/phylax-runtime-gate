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
