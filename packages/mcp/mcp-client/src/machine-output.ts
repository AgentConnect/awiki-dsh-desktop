/** Per-connection exact protection for bearer values actually sent to its resource. @module */
import { performance } from 'node:perf_hooks'
import type { MachineSentBearer } from './machine-history.ts'

/** Private callbacks used only by one connection's SDK bridge. */
export interface MachineOutputProtection {
  /**
   * Pin the signing binding and redaction history for an SDK operation and its output.
   * @param operation - Work receiving the authorization check for its publication point.
   * @returns The result of the operation.
   */
  run<T>(operation: (assertActive: () => Promise<void>) => Promise<T>): Promise<T>
  /** Replace exact known bearer values in strings and JSON property names. */
  sanitize<T>(value: T): T
}

/** Bounded secret retention; no method exposes the retained bearer collection. */
export class MachineBearerRedactor {
  private readonly known = new Map<string, { until: number; acquiredAt: number; receipt?: string }>()
  private readonly expired = new Set<string>()
  private readonly clientIds = new Set<string>()
  private operations = 0
  private bytes = 0
  constructor(private readonly now: () => number = () => performance.now()) {}
  /** Register public identity facts obtained from the current signer lease.
   * @param clientId - Exact CIMD identity confirmed by the signer.
   */
  registerIdentity(clientId: string): void {
    if (!this.clientIds.has(clientId) && this.clientIds.size >= 16) throw new Error('machine_identity_history_full')
    this.clientIds.add(clientId)
  }
  /** Retain the exact locally signed proof before the AS receives it.
   * @param assertion - Actual complete client assertion, never a public argument.
   */
  rememberAssertion(assertion: string): void {
    if (assertion.length > 16384) throw new Error('invalid_client_assertion')
    this.remember(assertion, this.now(), 60000)
  }
  private maskClientAssertions(text: string): string {
    if (!this.clientIds.size) return text
    let attempts = 0
    const decode = (part: string): unknown => JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as unknown
    const https = (value: unknown): value is string => {
      if (typeof value !== 'string') return false
      try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && !url.hash } catch { return false }
    }
    // Maximal runs avoid backtracking on large non-JWT strings. Only the fixed client-auth claim set qualifies.
    return text.replace(/[A-Za-z0-9_.-]+/gu, (run) => {
      if (!run.includes('.')) return run
      const parts = run.split('.'); const offsets: number[] = []; let offset = 0
      for (const part of parts) { offsets.push(offset); offset += part.length + 1 }
      const spans: Array<{ start: number; end: number }> = []
      for (let i = 0; i + 2 < parts.length; i++) {
        // The loop bounds guarantee three segments and their offsets.
        const payloadPart = parts[i + 1] as string; const signature = (parts[i + 2] as string).slice(0, 86)
        if (!payloadPart || payloadPart.length > 16384 || signature.length !== 86) continue
        let payload: unknown
        try { payload = decode(payloadPart) } catch { continue }
        if (!payload || typeof payload !== 'object') continue
        const claims = payload as Record<string, unknown>
        if (Object.keys(claims).some(key => !['iss', 'sub', 'aud', 'iat', 'exp', 'jti'].includes(key))
          || !https(claims.iss) || !this.clientIds.has(claims.iss) || claims.sub !== claims.iss || !https(claims.aud)
          || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)
          || (claims.exp as number) <= (claims.iat as number) || (claims.exp as number) - (claims.iat as number) > 60
          || typeof claims.jti !== 'string' || !claims.jti || claims.jti.length > 128) continue
        const headerPart = parts[i] as string; const tailStart = Math.max(0, headerPart.length - 16384)
        for (let start = headerPart.indexOf('eyJ', tailStart); start >= 0; start = headerPart.indexOf('eyJ', start + 3)) {
          if (++attempts > 128) throw new Error('machine_output_assertion_limit')
          const headerText = headerPart.slice(start)
          if (headerText.length + payloadPart.length + 88 > 16384) continue
          let header: Record<string, unknown>
          // The base64url prefix eyJ decodes to the start of a JSON object.
          try { header = decode(headerText) as Record<string, unknown> } catch { continue }
          if (header.alg !== 'ES256' || (header.typ !== 'JWT' && header.typ !== 'client-authentication+jwt')
            || Object.keys(header).some(key => !['alg', 'typ', 'kid'].includes(key))
            || typeof header.kid !== 'string' || !/^[\x21-\x7e]{1,1024}$/u.test(header.kid)) continue
          const bytes = Buffer.from(signature, 'base64url')
          if (bytes.length !== 64 || bytes.toString('base64url') !== signature) continue
          spans.push({ start: (offsets[i] as number) + start, end: (offsets[i + 2] as number) + 86 }); break
        }
      }
      let result = ''; let previous = 0
      for (const span of spans) {
        // Ends advance with the candidate index. Slice contributes no text for overlapping spans.
        result += run.slice(previous, span.start) + '\u25a0\u25a0\u25a0'; previous = span.end
      }
      return result + run.slice(previous)
    })
  }
  private prune(): void {
    if (this.operations) return
    const now = this.now()
    for (const [value, record] of this.known) {
      if (record.until > now) continue
      if (record.receipt) this.expired.add(record.receipt)
      this.known.delete(value); this.bytes -= Buffer.byteLength(value)
    }
  }
  /** Retain an outgoing bearer for its full lifetime plus bounded network allowance.
   * @param value - Actual outgoing bearer, held only in this connection.
   * @param acquiredAt - Issuance attempt identity, distinguishing reuse from reissuance.
   * @param lifetime - Validated advertised Token lifetime in milliseconds.
   */
  remember(value: string, acquiredAt: number, lifetime: number): void {
    this.prune()
    const existing = this.known.get(value)
    if (!/^[\x21-\x7e]{1,32768}$/u.test(value) || !Number.isFinite(lifetime)
      || lifetime <= 0 || lifetime > 86400000) throw new Error('invalid_token_lifetime')
    const bytes = Buffer.byteLength(value)
    const until = this.now() + lifetime + 30000
    if (existing && existing.acquiredAt === acquiredAt && existing.until >= until) return
    if (!existing && (this.known.size >= 256 || this.bytes + bytes > 1048576)) throw new Error('machine_secret_retention_full')
    if (!existing) this.bytes += bytes
    this.known.set(value, { acquiredAt, until: Math.max(existing?.until ?? 0, until),
      ...(existing?.receipt ? { receipt: existing.receipt } : {}) })
  }
  /** Merge a receipt without restarting its interval on every ordinary reload.
   * @param records - Authenticated private history read from the connection store.
   */
  observe(records: readonly MachineSentBearer[]): void {
    for (const record of records) {
      if (this.known.get(record.value)?.receipt === record.receipt) continue
      this.remember(record.value, this.known.get(record.value)?.acquiredAt ?? 0, record.lifetime)
      const entry = this.known.get(record.value)
      if (entry) entry.receipt = record.receipt
    }
  }
  /** Take versions with a fully elapsed monotonic interval and no pinned SDK operation.
   * @returns Receipt ids only; no bearer values.
   */
  expiredReceipts(): string[] { this.prune(); return [...this.expired] }
  /** Acknowledge conditional persistence cleanup.
   * @param receipts - Successfully processed receipt versions.
   */
  acknowledgePruned(receipts: readonly string[]): void { for (const receipt of receipts) this.expired.delete(receipt) }
  /** Pin retention across SDK response parsing and asynchronous projection.
   * @returns Idempotent release after sanitization completes.
   */
  begin(): () => void {
    this.prune(); this.operations++
    let released = false
    return () => { if (!released) { released = true; this.operations--; this.prune() } }
  }
  /** Clone JSON and redact exact values, preserving ordinary properties on key collisions.
   * @param value - SDK data or a diagnostic string from this connection.
   * @returns Sanitized data without mutating the SDK response.
   */
  sanitize<T>(value: T): T {
    const secrets = [...new Set([...this.known.keys()].flatMap(value => [value, JSON.stringify(value).slice(1, -1)]))]
      .sort((a, b) => b.length - a.length)
    // Bearers are ASCII. A non-ASCII marker cannot create a different retained bearer at a replacement boundary.
    const marker = '\u25a0\u25a0\u25a0'
    const text = (input: string) => {
      for (const secret of secrets) input = input.split(secret).join(marker)
      return this.maskClientAssertions(input)
    }
    if (typeof value === 'string') return text(value) as T
    if (value === null || typeof value !== 'object') return value
    const clone = (input: object): object => Array.isArray(input)
      ? [] : Object.create(Object.getPrototypeOf(input) === null ? null : Object.prototype) as object
    const result = clone(value)
    const seen = new WeakMap<object, object>([[value, result]])
    const pending: Array<{ source: object; target: object }> = [{ source: value, target: result }]
    for (let entry = pending.pop(); entry; entry = pending.pop()) {
      const { source, target } = entry
      const ordinary = new Set(Object.keys(source).filter(key => text(key) === key))
      for (const [key, child] of Object.entries(source) as [string, unknown][]) {
        let safeKey = Array.isArray(source) ? key : text(key)
        if (safeKey !== key) {
          const base = safeKey; let suffix = 0
          while (ordinary.has(safeKey) || Object.hasOwn(target, safeKey)) {
            const digits = String(++suffix).replace(/[0-9]/gu, digit => String.fromCharCode(0xff10 + Number(digit)))
            safeKey = `${base}\u00b7${digits}`
          }
        }
        let safeChild: unknown = child
        if (typeof child === 'string') safeChild = text(child)
        else if (child !== null && typeof child === 'object') {
          let targetChild = seen.get(child)
          if (!targetChild) {
            targetChild = clone(child)
            seen.set(child, targetChild)
            pending.push({ source: child, target: targetChild })
          }
          safeChild = targetChild
        }
        Object.defineProperty(target, safeKey, { value: safeChild, enumerable: true, configurable: true, writable: true })
      }
    }
    return result as T
  }
}
