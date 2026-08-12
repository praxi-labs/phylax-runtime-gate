import { PhylaxSdk } from '@phylax/sdk'
import type { PhylaxResult, VerificationResult } from '@phylax/sdk'

import { TtlCache } from './cache.js'
import { GateBlockedError } from './types.js'
import type {
  CheckInput,
  FailMode,
  GateDecision,
  GateResult,
  RuntimeGateOptions,
} from './types.js'

const DEFAULT_ALLOW_TTL_MS = 60_000
const DEFAULT_DENY_TTL_MS = 900_000
const DEFAULT_TIMEOUT_MS = 5_000

function resolveArtifact(input: CheckInput): string {
  if (input.artifact) {
    return input.artifact
  }
  if (typeof input.tool === 'string') {
    return input.tool
  }
  return String(input.tool?.artifact ?? input.tool?.name ?? '')
}

function normaliseDecision(verdict: unknown): GateDecision {
  const value = String(verdict ?? '').toLowerCase()
  if (value === 'block' || value === 'deny') {
    return 'block'
  }
  if (value === 'warn') {
    return 'warn'
  }
  if (value === 'allow') {
    return 'allow'
  }
  // An unrecognised verdict is treated as a block. A verdict added in a later
  // API version must stop execution rather than pass through it.
  return 'block'
}

export class RuntimeGate {
  readonly #sdk: PhylaxSdk
  readonly #cache: TtlCache<GateResult>
  readonly #policy: string | undefined
  readonly #failMode: FailMode
  readonly #allowTtl: number
  readonly #denyTtl: number
  readonly #timeoutMs: number
  readonly #unknownAs: GateDecision
  readonly #onDecision: ((result: GateResult) => void) | undefined

  constructor(options: RuntimeGateOptions) {
    if (!options.apiKey?.trim()) {
      throw new TypeError(
        'A Phylax API key is required. Create one at https://app.phyi.dev/marketplace/keys',
      )
    }

    this.#sdk = new PhylaxSdk({
      apiToken: options.apiKey,
      baseUrl: options.baseUrl,
      timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      userAgent: '@phylax/runtime-gate/0.1.0',
      fetch: options.fetch,
    })

    this.#cache = new TtlCache<GateResult>(options.cacheMaxEntries ?? 1000)
    this.#policy = options.policy
    this.#failMode = options.failMode ?? 'closed'
    this.#allowTtl = options.allowCacheTtlMs ?? DEFAULT_ALLOW_TTL_MS
    this.#denyTtl = options.denyCacheTtlMs ?? DEFAULT_DENY_TTL_MS
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.#unknownAs = options.unknownAs ?? 'allow'
    this.#onDecision = options.onDecision
  }

  async check(input: CheckInput): Promise<GateResult> {
    const artifact = resolveArtifact(input)
    if (!artifact) {
      return this.#emit({
        decision: 'block',
        reason: 'No artifact reference supplied to the gate',
        timestamp: new Date().toISOString(),
        cached: false,
        degraded: false,
      })
    }

    const policy = input.policy ?? this.#policy
    const key = `${artifact}::${policy ?? 'default'}`

    const cached = this.#cache.get(key)
    if (cached) {
      return this.#emit({ ...cached, cached: true })
    }

    const result = await this.#sdk.artifacts.verify(artifact, {
      ...(policy ? { policy } : {}),
      ...(input.signal ? { signal: input.signal } : {}),
    })

    const gateResult = this.#toGateResult(artifact, result, input.failMode)

    if (!gateResult.degraded) {
      this.#cache.set(
        key,
        gateResult,
        gateResult.decision === 'block' ? this.#denyTtl : this.#allowTtl,
      )
    }

    return this.#emit(gateResult)
  }

  async checkMany(
    artifacts: string[],
    options: Omit<CheckInput, 'tool' | 'artifact'> = {},
  ): Promise<GateResult[]> {
    return Promise.all(
      artifacts.map(artifact => this.check({ ...options, tool: artifact, artifact })),
    )
  }

  async enforce(input: CheckInput): Promise<GateResult> {
    const result = await this.check(input)
    if (result.decision === 'block') {
      throw new GateBlockedError(result)
    }
    return result
  }

  clearCache(): void {
    this.#cache.clear()
  }

  #toGateResult(
    artifact: string,
    result: PhylaxResult<VerificationResult>,
    overrideFailMode: FailMode | undefined,
  ): GateResult {
    const timestamp = new Date().toISOString()

    if (result.success) {
      const data = result.data as Record<string, unknown>
      const attestation = data['attestation'] as
        | { id?: string }
        | string
        | undefined

      // The network answers ALLOW with coverage "none" for anything it has not
      // evaluated, rather than 404, so one unknown entry does not break a batch.
      // That is the right transport answer and the wrong security answer for an
      // organization that wants to run only what has been seen, so the decision
      // for an uncovered artifact is the caller's to make.
      const uncovered = data['coverage'] === 'none'

      return {
        decision: uncovered
          ? this.#unknownAs
          : normaliseDecision(data['verdict']),
        reason: uncovered
          ? 'This artifact has not been evaluated by the network'
          : String(data['reason'] ?? data['verdict'] ?? 'evaluated'),
        riskScore:
          typeof data['risk_score'] === 'number'
            ? (data['risk_score'] as number)
            : typeof data['score'] === 'number'
              ? (data['score'] as number)
              : undefined,
        policies: Array.isArray(data['policies'])
          ? (data['policies'] as string[])
          : undefined,
        artifact,
        attestationId:
          typeof attestation === 'object' && attestation
            ? attestation.id
            : typeof data['attestationId'] === 'string'
              ? (data['attestationId'] as string)
              : undefined,
        timestamp,
        cached: false,
        degraded: false,
      }
    }

    const failMode = overrideFailMode ?? this.#failMode

    return {
      decision: failMode === 'open' ? 'allow' : 'block',
      reason:
        failMode === 'open'
          ? `Phylax unreachable (${result.code}), failing open: ${result.error}`
          : `Phylax unreachable (${result.code}), failing closed: ${result.error}`,
      artifact,
      timestamp,
      cached: false,
      degraded: true,
    }
  }

  #emit(result: GateResult): GateResult {
    this.#onDecision?.(result)
    return result
  }

  get timeoutMs(): number {
    return this.#timeoutMs
  }
}
