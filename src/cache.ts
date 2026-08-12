export interface CacheEntry<T> {
  value: T
  expiresAt: number
}

export class TtlCache<T> {
  readonly #entries = new Map<string, CacheEntry<T>>()
  readonly #maxEntries: number
  readonly #now: () => number

  constructor(maxEntries = 1000, now: () => number = Date.now) {
    this.#maxEntries = maxEntries
    this.#now = now
  }

  get(key: string): T | undefined {
    const entry = this.#entries.get(key)
    if (!entry) {
      return undefined
    }
    if (entry.expiresAt <= this.#now()) {
      this.#entries.delete(key)
      return undefined
    }
    this.#entries.delete(key)
    this.#entries.set(key, entry)
    return entry.value
  }

  set(key: string, value: T, ttlMs: number): void {
    if (ttlMs <= 0) {
      return
    }
    if (this.#entries.size >= this.#maxEntries) {
      const oldest = this.#entries.keys().next()
      if (!oldest.done) {
        this.#entries.delete(oldest.value)
      }
    }
    this.#entries.set(key, { value, expiresAt: this.#now() + ttlMs })
  }

  delete(key: string): void {
    this.#entries.delete(key)
  }

  clear(): void {
    this.#entries.clear()
  }

  get size(): number {
    return this.#entries.size
  }
}
