/** Encrypted, cross-process fenced machine connection storage. @module */
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto'
import { mkdir, readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { withFileLock, writeFileAtomic } from '@deepseek-ai/dsh-atomic-write'
import { MACHINE_HISTORY_BYTES, MACHINE_HISTORY_COUNT, MACHINE_TOKEN_MAX_LIFETIME } from './machine-history.ts'
import type { MachineSentBearer } from './machine-history.ts'

/** Opaque bearer and its exact local partition; never a public connection description. */
export interface MachineToken {
  token: string
  expiresAt: number
  acquiredAt: number
  scopes: string[]
  partition: string
  issueId?: string
}
interface CipherBox { iv: string; tag: string; ciphertext: string }
interface Migration { id: string; fingerprint: string; quarantineEvidence?: string }
type History = { format: 1; status: 'complete'; records: MachineSentBearer[] }
  | { format: 1; status: 'migration'; migration: Migration; records: MachineSentBearer[] }
interface Row {
  schema: 1 | 2
  generation: number
  active: boolean
  partition: string
  activationId?: string
  retryNotBefore?: number
  iv?: string
  tag?: string
  ciphertext?: string
  cipherGeneration?: number
  historyVersion?: 1
  history?: CipherBox
  historyMigration?: unknown
}
/** Safe private-store facts; no credential or unauthenticated migration qualification is returned. */
export interface MachineStoreState {
  generation: number
  active: boolean
  migrationId?: string
  quarantineEvidence?: string
  historyUnavailable?: boolean
}

/** Stores encrypted credentials separately for one persistent connection id. */
export class MachineConnectionStore {
  private readonly file: string
  private readonly historyPurpose: string
  constructor(private readonly root: string, connectionId: string, private readonly key: () => Promise<Buffer>) {
    if (!/^[A-Za-z0-9_-]{1,128}$/u.test(connectionId)) throw new Error('invalid_connection_id')
    const digest = createHash('sha256').update(connectionId).digest('hex')
    this.file = join(root, digest + '.json')
    this.historyPurpose = `@deepseek-ai/dsh-mcp-client/sent-bearer-history/1:${digest}`
  }
  private view(row: Row, history?: History): MachineStoreState {
    return { generation: row.generation, active: row.active,
      ...(!history ? { historyUnavailable: true } : history.status === 'migration' ? {
        migrationId: history.migration.id,
        ...(history.migration.quarantineEvidence ? { quarantineEvidence: history.migration.quarantineEvidence } : {}),
      } : {}) }
  }
  private async authenticatedView(row: Row): Promise<MachineStoreState> {
    if (row.schema !== 2) return this.view(row)
    try {
      const key = await this.key()
      try { return this.view(row, this.decodeHistory(row, key)) } finally { key.fill(0) }
    } catch { return this.view(row) }
  }
  /** Read the fence and only authenticated history qualifications.
   * @returns Safe lifecycle facts; unavailable authentication is a closed gate, not empty history.
   */
  async state(): Promise<MachineStoreState | undefined> {
    const row = await this.read()
    return row && this.authenticatedView(row)
  }
  private frame(row: Row | undefined, generation: number, active: boolean, partition: string, activationId?: string): Row {
    return { schema: 2, generation, active, partition, historyVersion: 1,
      ...(row?.retryNotBefore === undefined ? {} : { retryNotBefore: row.retryNotBefore }),
      ...(activationId ? { activationId } : {}) }
  }
  private fingerprint(row: Row): string {
    return createHash('sha256').update(JSON.stringify([row.generation, row.partition,
      row.cipherGeneration ?? row.generation, row.iv ?? '', row.tag ?? '', row.ciphertext ?? ''])).digest('hex')
  }
  private historyAad(row: Row): Buffer { return Buffer.from(`${this.historyPurpose}:${this.fingerprint(row)}`) }
  private requireComplete(history: History): void {
    if (history.status !== 'complete') throw new Error('machine_history_migration_required')
  }
  /** Create only absent fresh state; a complete empty history is authenticated too.
   * @param partition - Full identity, key, policy and resource partition.
   * @returns Active generation or a closed legacy/credential failure.
   */
  async open(partition: string): Promise<number> {
    return this.transaction(async (write) => {
      let row = await this.read()
      if (row && !row.active) throw new Error('connection_disabled')
      const key = await this.key()
      try {
        const history: History = row ? this.decodeHistory(row, key) : { format: 1, status: 'complete', records: [] }
        this.requireComplete(history)
        if (!row || row.partition !== partition) {
          if (row) this.seedCurrent(row, history, key)
          row = this.encodeHistory(this.frame(row, (row?.generation ?? 0) + 1, true, partition), history, key)
          await write(row)
        }
        return row.generation
      } finally { key.fill(0) }
    })
  }
  private tokenWithKey(row: Row, key: Buffer): MachineToken | undefined {
    if (!row.ciphertext && !row.iv && !row.tag) return undefined
    try {
      if (!row.ciphertext || !row.iv || !row.tag) throw new Error()
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(row.iv, 'base64url'))
      decipher.setAAD(Buffer.from(`${row.cipherGeneration ?? row.generation}:${row.partition}`)); decipher.setAuthTag(Buffer.from(row.tag, 'base64url'))
      const token = JSON.parse(Buffer.concat([decipher.update(Buffer.from(row.ciphertext, 'base64url')), decipher.final()]).toString('utf8')) as MachineToken | null
      if (!token || token.partition !== row.partition || typeof token.token !== 'string' || !/^[\x21-\x7e]{1,32768}$/u.test(token.token)
        || !Number.isSafeInteger(token.expiresAt) || !Number.isSafeInteger(token.acquiredAt)
        || !Array.isArray(token.scopes) || !token.scopes.every(value => typeof value === 'string')) throw new Error()
      return token
    } catch { throw new Error('credential_store_unavailable') }
  }
  /** Read only a matching active generation with complete authenticated history.
   * @param generation - Expected generation.
   * @param partition - Exact partition.
   * @returns Current decrypted Token, if any.
   */
  async token(generation: number, partition: string): Promise<MachineToken | undefined> {
    const row = await this.read(); this.check(row, generation, partition)
    const key = await this.key()
    try { this.requireComplete(this.decodeHistory(row, key)); return this.tokenWithKey(row, key) } finally { key.fill(0) }
  }
  private decodeHistory(row: Row, key: Buffer): History {
    try {
      if (row.schema !== 2 || !row.history) throw new Error()
      const box = row.history
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'base64url'))
      decipher.setAAD(this.historyAad(row)); decipher.setAuthTag(Buffer.from(box.tag, 'base64url'))
      const text = Buffer.concat([decipher.update(Buffer.from(box.ciphertext, 'base64url')), decipher.final()]).toString('utf8')
      if (Buffer.byteLength(text) > MACHINE_HISTORY_BYTES) throw new Error()
      const history = JSON.parse(text) as {
        format?: number
        status: string
        migration?: Migration
        records?: Array<MachineSentBearer | null>
      } | null
      if (!history || history.format !== 1 || !['complete', 'migration'].includes(history.status)
        || !Array.isArray(history.records) || history.records.length > MACHINE_HISTORY_COUNT) throw new Error()
      if (history.status === 'migration') {
        const migration = history.migration
        if (!migration || typeof migration.id !== 'string' || !/^[A-Za-z0-9-]{16,64}$/u.test(migration.id)
          || typeof migration.fingerprint !== 'string' || !/^[a-f0-9]{64}$/u.test(migration.fingerprint)) throw new Error()
        if (migration.quarantineEvidence !== undefined && (typeof migration.quarantineEvidence !== 'string'
          || !/^[A-Za-z0-9_.:-]{1,128}$/u.test(migration.quarantineEvidence))) throw new Error()
      } else if ('migration' in history) throw new Error()
      const values = new Set<string>()
      for (const record of history.records) {
        if (!record || typeof record.value !== 'string' || !/^[\x21-\x7e]{1,32768}$/u.test(record.value)
          || typeof record.receipt !== 'string' || !/^[A-Za-z0-9-]{16,64}$/u.test(record.receipt)
          || typeof record.source !== 'string' || record.source.length > 160
          || !Number.isSafeInteger(record.lifetime) || record.lifetime <= 0 || record.lifetime > MACHINE_TOKEN_MAX_LIFETIME
          || values.has(record.value)) throw new Error()
        values.add(record.value)
      }
      return history as History
    } catch { throw new Error('credential_store_unavailable') }
  }
  private encodeHistory(row: Row, history: History, key: Buffer): Row {
    const text = JSON.stringify(history)
    if (history.records.length > MACHINE_HISTORY_COUNT || Buffer.byteLength(text) > MACHINE_HISTORY_BYTES) throw new Error('machine_secret_retention_full')
    const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv)
    cipher.setAAD(this.historyAad(row))
    const ciphertext = Buffer.concat([cipher.update(text), cipher.final()])
    const next: Row = { ...row, schema: 2, historyVersion: 1,
      history: { iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url') } }
    // Mirrors are only display metadata. All qualification comes from the authenticated payload.
    if (history.status === 'migration') next.historyMigration = history.migration
    else delete next.historyMigration
    return next
  }
  private tokenSource(token: MachineToken): string { return token.issueId ?? `legacy:${token.acquiredAt}:${token.expiresAt}:${token.partition}` }
  private mergeToken(records: MachineSentBearer[], token: MachineToken): boolean {
    const lifetime = token.expiresAt - token.acquiredAt
    if (!Number.isSafeInteger(lifetime) || lifetime <= 0 || lifetime > MACHINE_TOKEN_MAX_LIFETIME) throw new Error('invalid_token_lifetime')
    const source = this.tokenSource(token); const previous = records.find(record => record.value === token.token)
    if (previous?.source === source) return false
    const next = { value: token.token, source, lifetime: Math.max(previous?.lifetime ?? 0, lifetime), receipt: randomUUID() }
    if (previous) records.splice(records.indexOf(previous), 1, next)
    else records.push(next)
    return true
  }
  private seedCurrent(row: Row, history: History, key: Buffer): void {
    const token = this.tokenWithKey(row, key)
    if (token) this.mergeToken(history.records, token)
  }
  /** Persist material before the resource receives it.
   * @param generation - Expected active generation.
   * @param partition - Exact partition.
   * @param token - Actual outgoing bearer.
   * @param authorize - Recheck the signer after key resolution.
   * @returns Private authenticated records for the redactor only.
   */
  async rememberSent(
    generation: number, partition: string, token: MachineToken, authorize: () => Promise<void>,
  ): Promise<MachineSentBearer[]> {
    return this.transaction(async (write) => {
      const row = await this.read(); this.check(row, generation, partition)
      const key = await this.key()
      try {
        const history = this.decodeHistory(row, key); this.requireComplete(history)
        await authorize()
        if (this.mergeToken(history.records, token)) { await authorize(); await write(this.encodeHistory(row, history, key)) }
        return history.records
      } finally { key.fill(0) }
    })
  }
  /** Reload authenticated records, never treating a missing envelope as an empty complete history.
   * @returns Private records; never forward them to users or logs.
   */
  async sentHistory(): Promise<MachineSentBearer[]> {
    const row = await this.read()
    if (!row) return []
    const key = await this.key()
    try { const history = this.decodeHistory(row, key); this.requireComplete(history); return history.records } finally { key.fill(0) }
  }
  /** Remove only fully elapsed receipt versions; keep enablement and retry metadata unchanged.
   * @param receipts - Exact expired versions from this process's monotonic observer.
   */
  async pruneSentHistory(receipts: readonly string[]): Promise<void> {
    if (!receipts.length) return
    await this.transaction(async (write) => {
      const row = await this.read()
      if (!row) return
      const key = await this.key()
      try {
        const history = this.decodeHistory(row, key); const remove = new Set(receipts)
        const removed = history.records.filter(record => remove.has(record.receipt))
        if (!removed.length) return
        history.records = history.records.filter(record => !remove.has(record.receipt))
        const current = this.tokenWithKey(row, key); const next = { ...row }
        if (current && removed.some(record => record.value === current.token && record.source === this.tokenSource(current))) {
          delete next.iv; delete next.tag; delete next.ciphertext; delete next.cipherGeneration
        }
        await write(this.encodeHistory(next, history, key))
      } finally { key.fill(0) }
    })
  }
  /** Commit a new current Token only after retaining its predecessor.
   * @param generation - Expected generation.
   * @param value - New private Token.
   * @param authorize - Current signer permission inside the lock.
   */
  async commit(generation: number, value: MachineToken, authorize?: () => Promise<void>): Promise<void> {
    await this.transaction(async (write) => {
      const row = await this.read(); this.check(row, generation, value.partition)
      const key = await this.key()
      try {
        const history = this.decodeHistory(row, key); this.requireComplete(history)
        await authorize?.(); this.seedCurrent(row, history, key); await authorize?.()
        const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv)
        cipher.setAAD(Buffer.from(`${generation}:${value.partition}`))
        const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()])
        const next = { ...row, cipherGeneration: generation, iv: iv.toString('base64url'),
          tag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url') }
        await write(this.encodeHistory(next, history, key))
      } finally { key.fill(0) }
    })
  }
  /** Final fence-only read after all asynchronous signer and history checks, immediately before dispatch or return.
   * @param generation - Expected generation.
   * @param partition - Exact partition.
   */
  async assertCurrent(generation: number, partition: string): Promise<void> { this.check(await this.read(), generation, partition) }
  /** Persist AS throttling.
   * @param generation - Current generation.
   * @param partition - Exact partition.
   * @param until - Retry deadline.
   */
  async defer(generation: number, partition: string, until: number): Promise<void> {
    await this.transaction(async (write) => {
      const row = await this.read(); this.check(row, generation, partition)
      await write({ ...row, retryNotBefore: Math.max(row.retryNotBefore ?? 0, until) })
    })
  }
  /** Read the shared retry deadline.
   * @param generation - Current generation.
   * @param partition - Exact partition.
   * @returns Earliest allowed retry.
   */
  async retryAt(generation: number, partition: string): Promise<number> {
    const row = await this.read(); this.check(row, generation, partition); return row.retryNotBefore ?? 0
  }
  /** Compare and clear the Token used by one completed request.
   * @param generation - Request generation.
   * @param token - Request Token and its issuance identity.
   */
  async invalidate(generation: number, token: MachineToken): Promise<void> {
    await this.transaction(async (write) => {
      const row = await this.read()
      if (!row?.active || row.generation !== generation || row.partition !== token.partition) return
      const key = await this.key()
      try {
        const history = this.decodeHistory(row, key)
        this.requireComplete(history)
        const current = this.tokenWithKey(row, key)
        if (!current || current.token !== token.token || this.tokenSource(current) !== this.tokenSource(token)) return
        this.seedCurrent(row, history, key)
        await write(this.encodeHistory(this.frame(row, generation, true, token.partition, row.activationId), history, key))
      } finally { key.fill(0) }
    })
  }
  private check(row: Row | undefined, generation: number, partition: string): asserts row is Row {
    if (!row || !row.active || row.generation !== generation || row.partition !== partition) throw new Error('connection_generation_changed')
  }
  private async read(): Promise<Row | undefined> {
    try {
      const info = await stat(this.file)
      if (info.size > 2097152
        || (process.platform !== 'win32' && (info.mode & 0o077) !== 0)) throw new Error()
      const row = JSON.parse(await readFile(this.file, 'utf8')) as Row
      if (![1, 2].includes(row.schema) || !Number.isSafeInteger(row.generation) || typeof row.active !== 'boolean' || typeof row.partition !== 'string') throw new Error()
      if (row.cipherGeneration !== undefined && !Number.isSafeInteger(row.cipherGeneration)) throw new Error()
      if (row.activationId !== undefined && (typeof row.activationId !== 'string' || !/^[A-Za-z0-9-]{16,64}$/u.test(row.activationId))) throw new Error()
      return row
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
      throw new Error('credential_store_unavailable')
    }
  }
  private async transaction<T>(run: (write: (row: Row) => Promise<void>) => Promise<T>): Promise<T> {
    await mkdir(this.root, { recursive: true, mode: 0o700 })
    const lock = { entered: false }
    try {
      // The current Host owns the lock and the write; no detached writer can outlive it.
      return await withFileLock(this.file, async () => {
        lock.entered = true
        return run(async (row) => {
          try { await writeFileAtomic(this.file, JSON.stringify(row), { mode: 0o600, dirMode: 0o700 }) }
          catch { throw new Error('credential_store_unavailable') }
        })
      }, { waitMs: 10000 })
    } catch (error) {
      if (!lock.entered) throw new Error('connection_store_locked')
      throw error
    }
  }
}
