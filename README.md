# @phyi/runtime-gate

Check tools, packages and actions against policy before an AI agent executes them.

An agent's tool set is not fixed at build time. It discovers tools while it works, and a tool description is read as trusted context by the model. `@phyi/runtime-gate` sits between your agent and its tools, verifies what is about to run, and refuses anything your policy blocks. It catches three things a build time check cannot: a tool published after your last build, a definition that changed after it was approved, and arguments that violate policy even when the tool itself is allowed.

## Install

```sh
npm install @phyi/runtime-gate
```

## Usage

<details open>
<summary><b>Quickstart</b>: wrap a tool call so a blocked artifact never executes</summary>

```typescript
import { RuntimeGate } from '@phyi/runtime-gate'

const gate = new RuntimeGate({
  apiKey: process.env.PHYLAX_API_KEY,
})

async function runTool(tool: Tool, input: unknown) {
  const decision = await gate.check({ tool, input })

  if (decision.decision === 'block') {
    throw new Error(`Blocked by policy: ${decision.reason}`)
  }

  return await tool.execute(input)
}
```

`enforce` does the same thing and throws a `GateBlockedError` for you:

```typescript
await gate.enforce({ tool })
return await tool.execute(input)
```

</details>

<details>
<summary><b>Audit every decision</b></summary>

```typescript
const gate = new RuntimeGate({
  apiKey: process.env.PHYLAX_API_KEY,
  onDecision: entry => logger.info(entry),
})
```

Each entry carries the decision, reason, risk score, matched policies, artifact, attestation id and timestamp, plus whether it was served from cache and whether it was made while degraded.

</details>

## What happens when Phylax is unreachable

This is the decision that matters most, and the one most gates never make explicitly. The gate is inline with execution, so an outage becomes an availability question at the worst moment.

| Mode | On error | Use when |
| --- | --- | --- |
| `closed` (default) | Treat as `block` | The agent can take real world actions: writes, payments, deploys, outbound mail |
| `open` | Treat as `allow`, flagged degraded | The agent is read only and an outage would break something a human is waiting on |

Choose per tool rather than per application. The same agent can fail closed on a filesystem write and open on a search query.

```typescript
const gate = new RuntimeGate({ apiKey, failMode: 'closed' })

await gate.check({ tool: searchTool, failMode: 'open' })
```

Every decision made during an outage carries `degraded: true`, so an outage never looks like a clean allow in your audit trail. Degraded decisions are never cached.

## Caching

Caching keeps the gate off the critical path, but a cached allow means the agent is acting on a verdict that may already be stale.

| Option | Default | Notes |
| --- | --- | --- |
| `allowCacheTtlMs` | `60000` | Keep short. Set `0` to disable. |
| `denyCacheTtlMs` | `900000` | Denials are safe to cache for longer. |
| `cacheMaxEntries` | `1000` | Least recently used entries are evicted. |

The cache key is the exact artifact reference plus the policy, never the tool name, so a version bump is always re-checked.

## Options

| Option | Default | Notes |
| --- | --- | --- |
| `apiKey` | required | Throws if absent. |
| `policy` | none | Default policy for every check. |
| `failMode` | `closed` | See above. |
| `timeoutMs` | `5000` | An unbounded await is a hang, not a security control. |
| `onDecision` | none | Audit callback, called for cached decisions too. |
| `baseUrl` | `https://api.phyi.dev` | |

## Keeping the gate off the critical path

The gate runs on every action, so its latency is your agent's latency.

Batch the checks for a plan before executing it rather than one round trip per step:

```typescript
const results = await gate.checkMany([
  'pkg:npm/express@4.18.2',
  'pkg:pypi/requests@2.32.3',
])
```

Await only before side effects, and keep the timeout aligned with your fail mode.

## License

MIT
