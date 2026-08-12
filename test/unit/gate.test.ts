import { describe, expect, it, vi } from 'vitest'

import { GateBlockedError, RuntimeGate } from '../../src/index.js'

function respond(body: unknown, status = 200) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function gateWith(fetchImpl: ReturnType<typeof vi.fn>, options = {}) {
  return new RuntimeGate({
    apiKey: 'phx_live_test',
    fetch: fetchImpl as never,
    ...options,
  })
}

describe('construction', () => {
  it('requires an API key', () => {
    expect(() => new RuntimeGate({ apiKey: '' })).toThrow(TypeError)
    expect(() => new RuntimeGate({ apiKey: '  ' })).toThrow(/API key is required/)
  })
})

describe('decisions', () => {
  it('allows a clean artifact', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW', risk_score: 8 }))
    const result = await gateWith(fetchImpl).check({ tool: 'pkg:npm/express@4.18.2' })

    expect(result.decision).toBe('allow')
    expect(result.riskScore).toBe(8)
    expect(result.degraded).toBe(false)
  })

  it('blocks a failing artifact', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'BLOCK', reason: 'malware' }))
    const result = await gateWith(fetchImpl).check({ tool: 'pkg:npm/bad@1' })

    expect(result.decision).toBe('block')
    expect(result.reason).toBe('malware')
  })

  it('treats warn as non blocking', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'WARN' }))
    const result = await gateWith(fetchImpl).check({ tool: 'pkg:npm/x@1' })

    expect(result.decision).toBe('warn')
  })

  it('blocks when no artifact reference is supplied', async () => {
    const fetchImpl = vi.fn()
    const result = await gateWith(fetchImpl).check({ tool: '' })

    expect(result.decision).toBe('block')
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('reads the artifact from a tool object', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW' }))
    await gateWith(fetchImpl).check({ tool: { name: 'pkg:npm/express@4.18.2' } })

    expect(JSON.parse(fetchImpl.mock.calls[0]![1].body as string).artifact).toBe(
      'pkg:npm/express@4.18.2',
    )
  })
})

describe('fail modes', () => {
  it('fails closed by default when Phylax is unreachable', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    const result = await gateWith(fetchImpl, { maxRetries: 1 }).check({
      tool: 'pkg:npm/x@1',
    })

    expect(result.decision).toBe('block')
    expect(result.degraded).toBe(true)
    expect(result.reason).toMatch(/failing closed/)
  })

  it('fails open when configured to', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    const result = await gateWith(fetchImpl, { failMode: 'open' }).check({
      tool: 'pkg:npm/x@1',
    })

    expect(result.decision).toBe('allow')
    expect(result.degraded).toBe(true)
    expect(result.reason).toMatch(/failing open/)
  })

  it('allows the fail mode to be overridden per call', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    const gate = gateWith(fetchImpl, { failMode: 'closed' })

    const readOnly = await gate.check({ tool: 'pkg:npm/x@1', failMode: 'open' })
    expect(readOnly.decision).toBe('allow')
  })

  it('marks a degraded decision so an outage is never a clean allow', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error('down'))
    const result = await gateWith(fetchImpl, { failMode: 'open' }).check({
      tool: 'pkg:npm/x@1',
    })

    expect(result.degraded).toBe(true)
  })
})

describe('caching', () => {
  it('serves a repeat check from cache', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW' }))
    const gate = gateWith(fetchImpl)

    const first = await gate.check({ tool: 'pkg:npm/x@1' })
    const second = await gate.check({ tool: 'pkg:npm/x@1' })

    expect(first.cached).toBe(false)
    expect(second.cached).toBe(true)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  it('keys the cache on the exact version, not the name', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW' }))
    const gate = gateWith(fetchImpl)

    await gate.check({ tool: 'pkg:npm/x@1.0.0' })
    await gate.check({ tool: 'pkg:npm/x@1.0.1' })

    expect(fetchImpl).toHaveBeenCalledTimes(2)
  })

  it('keys the cache on the policy as well', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW' }))
    const gate = gateWith(fetchImpl)

    await gate.check({ tool: 'pkg:npm/x@1', policy: 'strict' })
    await gate.check({ tool: 'pkg:npm/x@1', policy: 'lenient' })

    expect(fetchImpl).toHaveBeenCalledTimes(2)
  })

  it('never caches a degraded decision', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error('down'))
    const gate = gateWith(fetchImpl, { failMode: 'open' })

    await gate.check({ tool: 'pkg:npm/x@1' })
    await gate.check({ tool: 'pkg:npm/x@1' })

    expect(fetchImpl.mock.calls.length).toBeGreaterThan(1)
  })

  it('does not cache when the allow ttl is zero', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW' }))
    const gate = gateWith(fetchImpl, { allowCacheTtlMs: 0 })

    await gate.check({ tool: 'pkg:npm/x@1' })
    await gate.check({ tool: 'pkg:npm/x@1' })

    expect(fetchImpl).toHaveBeenCalledTimes(2)
  })
})

describe('enforce', () => {
  it('throws on a block', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'BLOCK', reason: 'bad' }))
    await expect(
      gateWith(fetchImpl).enforce({ tool: 'pkg:npm/bad@1' }),
    ).rejects.toBeInstanceOf(GateBlockedError)
  })

  it('returns the result on an allow', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW' }))
    const result = await gateWith(fetchImpl).enforce({ tool: 'pkg:npm/x@1' })

    expect(result.decision).toBe('allow')
  })

  it('carries the full result on the thrown error', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'BLOCK', reason: 'bad' }))
    try {
      await gateWith(fetchImpl).enforce({ tool: 'pkg:npm/bad@1' })
      expect.unreachable()
    } catch (error) {
      expect(error).toBeInstanceOf(GateBlockedError)
      expect((error as GateBlockedError).result.artifact).toBe('pkg:npm/bad@1')
    }
  })
})

describe('audit', () => {
  it('reports every decision to the audit callback', async () => {
    const seen: string[] = []
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW' }))
    const gate = gateWith(fetchImpl, {
      onDecision: (r: { decision: string }) => seen.push(r.decision),
    })

    await gate.check({ tool: 'pkg:npm/x@1' })
    await gate.check({ tool: 'pkg:npm/x@1' })

    expect(seen).toEqual(['allow', 'allow'])
  })

  it('stamps every decision with a timestamp', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW' }))
    const result = await gateWith(fetchImpl).check({ tool: 'pkg:npm/x@1' })

    expect(() => new Date(result.timestamp).toISOString()).not.toThrow()
  })
})

describe('checkMany', () => {
  it('checks a batch and returns one result per artifact', async () => {
    const fetchImpl = vi.fn().mockImplementation(() => respond({ verdict: 'ALLOW' }))
    const results = await gateWith(fetchImpl).checkMany([
      'pkg:npm/a@1',
      'pkg:npm/b@2',
    ])

    expect(results).toHaveLength(2)
    expect(results.every(r => r.decision === 'allow')).toBe(true)
  })
})
