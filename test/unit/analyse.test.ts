/**
 * Gating on what a tool does, rather than on what its name is known for.
 *
 * A lookup answers about a reference, so a tool the network has never seen
 * falls to `unknownAs` — which defaults to allow, because a 404 would break a
 * batch and warning on everything unseen trains people to ignore warnings. For
 * a runtime gate that is precisely backwards: the tool worth stopping is rarely
 * one that has already been attested.
 *
 * Passing `files` turns the check into an analysis. These pin that, and the
 * three things that must not regress with it: the cache keys on content rather
 * than name, an outage still fails closed, and a static-only pass can be
 * refused.
 */

import { describe, expect, it } from 'vitest'

import { RuntimeGate } from '../../src/gate.js'

const FILES = {
  'package.json': '{"name":"demo"}',
  'index.js': 'require("child_process").execSync(process.env.CMD)\n',
}

const CHAMPION_BLOCK = {
  artifact: 'demo',
  verdict: 'BLOCK',
  coverage: 'champion',
  confidence: 0.9,
  engine: { version: 'v1', analysers: 3, dissent: false },
  reasons: ['command injection in index.js'],
}

const STATIC_ALLOW = {
  artifact: 'demo',
  verdict: 'ALLOW',
  coverage: 'static',
  confidence: 0.2,
  engine: { version: 'none', analysers: 0, dissent: false },
  reasons: [],
}

/**
 * The gate holds its SDK in a private field, so tests inject through the
 * documented `fetch` seam instead of reaching inside.
 */
function gateWithFetch(
  body: unknown,
  options: Record<string, unknown> = {},
): { gate: RuntimeGate; calls: string[] } {
  const calls: string[] = []
  const fetchImpl = (async (url: string) => {
    calls.push(String(url))
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }) as unknown as typeof fetch

  return {
    gate: new RuntimeGate({ apiKey: 'phx_test', fetch: fetchImpl, ...options }),
    calls,
  }
}

describe('checking with files', () => {
  it('analyses instead of looking the name up', async () => {
    const { gate, calls } = gateWithFetch(CHAMPION_BLOCK)
    const result = await gate.check({ tool: 'demo', files: FILES })

    expect(calls[0]).toContain('/v1/artifacts/analyse')
    expect(result.decision).toBe('block')
    expect(result.reason).toContain('command injection')
  })

  it('looks up when no files are supplied', async () => {
    const { gate, calls } = gateWithFetch({ verdict: 'ALLOW', coverage: 'none' })
    await gate.check({ tool: 'pkg:npm/demo@1.0.0' })
    expect(calls[0]).toContain('/v1/artifacts/verify')
  })

  it('reports the champion verdict rather than falling to unknownAs', async () => {
    /**
     * The regression this exists for. Without files this tool is uncovered and
     * the gate would answer `allow`; with them it is judged on what it does.
     */
    const { gate } = gateWithFetch(CHAMPION_BLOCK, { unknownAs: 'allow' })
    const result = await gate.check({ tool: 'never-seen', files: FILES })
    expect(result.decision).toBe('block')
  })
})

describe('requireChampions', () => {
  it('refuses an allow that only the static scanner produced', async () => {
    const { gate } = gateWithFetch(STATIC_ALLOW, { requireChampions: true })
    const result = await gate.check({ tool: 'demo', files: FILES })

    expect(result.decision).toBe('block')
    expect(result.reason).toContain('static scanner alone')
  })

  it('accepts a static allow when not set, but says what backed it', async () => {
    const { gate } = gateWithFetch(STATIC_ALLOW)
    const result = await gate.check({ tool: 'demo', files: FILES })

    expect(result.decision).toBe('allow')
    expect(result.reason).toContain('coverage static')
  })

  it('does not turn a champion block into something softer', async () => {
    const { gate } = gateWithFetch(CHAMPION_BLOCK, { requireChampions: true })
    expect((await gate.check({ tool: 'demo', files: FILES })).decision).toBe('block')
  })
})

describe('caching an analysis', () => {
  it('keys on content, so an edited tool is re-analysed', async () => {
    let calls = 0
    const fetchImpl = (async () => {
      calls += 1
      return new Response(JSON.stringify(CHAMPION_BLOCK), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }) as unknown as typeof fetch

    const gate = new RuntimeGate({ apiKey: 'phx_test', fetch: fetchImpl })

    await gate.check({ tool: 'demo', files: FILES })
    await gate.check({ tool: 'demo', files: FILES })
    expect(calls).toBe(1)

    // Same name, changed source. A stale allow here is the whole risk.
    await gate.check({ tool: 'demo', files: { ...FILES, 'index.js': 'evil()\n' } })
    expect(calls).toBe(2)
  })
})

describe('when Phylax is unreachable', () => {
  it('still fails closed on the analysis path', async () => {
    const fetchImpl = (async () => {
      throw new TypeError('network down')
    }) as unknown as typeof fetch

    const gate = new RuntimeGate({ apiKey: 'phx_test', fetch: fetchImpl, maxRetries: 0 } as never)
    const result = await gate.check({ tool: 'demo', files: FILES })

    expect(result.decision).toBe('block')
    expect(result.degraded).toBe(true)
  })

  it('fails open on the analysis path when told to', async () => {
    const fetchImpl = (async () => {
      throw new TypeError('network down')
    }) as unknown as typeof fetch

    const gate = new RuntimeGate({
      apiKey: 'phx_test',
      fetch: fetchImpl,
      failMode: 'open',
    } as never)
    const result = await gate.check({ tool: 'demo', files: FILES })

    expect(result.decision).toBe('allow')
    expect(result.degraded).toBe(true)
  })
})
