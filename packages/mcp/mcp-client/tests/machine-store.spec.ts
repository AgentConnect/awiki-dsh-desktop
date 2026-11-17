/** Private encrypted history, receipt CAS and conservative legacy migration. No wall-clock 24-hour run. */
import { createCipheriv, createHash, randomBytes } from 'node:crypto'
import { chmod, mkdtemp, readdir, readFile, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, expect, it, vi } from 'vitest'
import * as atomicWrite from '@deepseek-ai/dsh-atomic-write'
import { MachineConnectionStore } from '../src/machine-store.ts'
import type { MachineToken } from '../src/machine-store.ts'
import { MachineBearerRedactor } from '../src/machine-output.ts'
const roots: string[] = []
afterEach(async () => { await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))) })
async function fixture(id = 'history') {
  const root = await mkdtemp(join(tmpdir(), 'mcp-history-')); roots.push(root)
  const store = new MachineConnectionStore(root, id, async () => Buffer.alloc(32, 73))
  const generation = await store.open('partition')
  const file = join(root, (await readdir(root)).find(name => name.endsWith('.json'))!)
  const token = (value: string, issueId: string): MachineToken => ({ token: value, issueId, partition: 'partition', acquiredAt: 1000, expiresAt: 61000, scopes: ['read'] })
  return { root, store, generation, file, token }
}

async function writeHistory(file: string, payload: unknown): Promise<void> {
  const row = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', Buffer.alloc(32, 73), iv)
  const fingerprint = createHash('sha256').update(JSON.stringify([row.generation, row.partition,
    row.cipherGeneration ?? row.generation, row.iv ?? '', row.tag ?? '', row.ciphertext ?? ''])).digest('hex')
  cipher.setAAD(Buffer.from('@deepseek-ai/dsh-mcp-client/sent-bearer-history/1:'
    + createHash('sha256').update('history').digest('hex') + ':' + fingerprint))
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final()])
  const history = { iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url') }
  await writeFile(file, JSON.stringify({ ...row, history }), { mode: 0o600 })
}

it('does not reuse a Token ciphertext as history or copy history to another connection', async () => {
  const f = await fixture()
  const token = f.token('private-purpose-bearer', 'purpose')
  await f.store.commit(f.generation, token)
  await f.store.rememberSent(f.generation, 'partition', token, async () => {})
  const original = JSON.parse(await readFile(f.file, 'utf8'))
  const substituted = { ...original, history: { iv: original.iv, tag: original.tag, ciphertext: original.ciphertext } }
  await writeFile(f.file, JSON.stringify(substituted), { mode: 0o600 })
  await expect(f.store.sentHistory()).rejects.toThrow('credential_store_unavailable')
  await writeFile(f.file, JSON.stringify(original), { mode: 0o600 })
  const other = new MachineConnectionStore(f.root, 'other', async () => Buffer.alloc(32, 73)); await other.open('partition')
  const file = (await readdir(f.root)).filter(name => name.endsWith('.json')).find(name => join(f.root, name) !== f.file)!
  const otherRow = JSON.parse(await readFile(join(f.root, file), 'utf8'))
  await writeFile(join(f.root, file), JSON.stringify({ ...otherRow, history: original.history }), { mode: 0o600 })
  await expect(other.sentHistory()).rejects.toThrow('credential_store_unavailable')
})

it('CAS cleanup preserves a newer receipt and does not reset the connection fence or retry deadline', async () => {
  const f = await fixture()
  const old = f.token('same-private-bearer', 'old-issue')
  await f.store.commit(f.generation, old)
  const previous = await f.store.rememberSent(f.generation, 'partition', old, async () => {})
  const renewed = { ...old, issueId: 'new-issue' }
  await f.store.commit(f.generation, renewed)
  const current = await f.store.rememberSent(f.generation, 'partition', renewed, async () => {})
  await f.store.defer(f.generation, 'partition', 999999)
  const state = await f.store.state()
  await f.store.pruneSentHistory([previous[0]!.receipt])
  expect((await f.store.sentHistory())[0]!.receipt).toBe(current[0]!.receipt)
  await f.store.pruneSentHistory([current[0]!.receipt])
  expect(await f.store.sentHistory()).toEqual([])
  expect(await f.store.state()).toEqual(state)
  expect(await f.store.retryAt(f.generation, 'partition')).toBe(999999)
  expect(await f.store.token(f.generation, 'partition')).toBeUndefined()
})

it('does not restart an unchanged receipt lifetime on every history reload', () => {
  let now = 0
  const redactor = new MachineBearerRedactor(() => now)
  const record = { value: 'private-expiring-bearer', source: 'issue', receipt: 'receipt-current-12345', lifetime: 1000 }
  redactor.observe([record]); now = 30000; redactor.observe([record]); now = 31001
  expect(redactor.expiredReceipts()).toEqual([record.receipt])
  expect(redactor.sanitize(record.value)).toBe(record.value)
  redactor.acknowledgePruned([record.receipt])
  redactor.observe([{ ...record, receipt: 'receipt-new-version-12345' }])
  expect(redactor.sanitize(record.value).includes(record.value)).toBe(false)
})

it('refuses an unsupported future state format without replacing it', async () => {
  const f = await fixture()
  const row = JSON.parse(await readFile(f.file, 'utf8')); row.schema = 3
  const raw = JSON.stringify(row); await writeFile(f.file, raw, { mode: 0o600 })
  await expect(f.store.state()).rejects.toThrow('credential_store_unavailable')
  expect((await readFile(f.file, 'utf8')) === raw).toBe(true)
})

it('does not silently evict a live receipt when durable history reaches its count budget', async () => {
  const f = await fixture()
  const records = Array.from({ length: 256 }, (_, index) => ({ value: `private-record-${index}`, source: `source-${index}`,
    receipt: `receipt-for-record-${index}-version`, lifetime: 86400000 }))
  await writeHistory(f.file, { format: 1, status: 'complete', records })
  const persisted = await readFile(f.file, 'utf8')
  await expect(f.store.rememberSent(f.generation, 'partition', f.token('overflow-private', 'overflow'), async () => {}))
    .rejects.toThrow('machine_secret_retention_full')
  expect((await f.store.sentHistory()).length).toBe(256)
  expect(await readFile(f.file, 'utf8')).toBe(persisted)
  expect((await f.store.state())!.active).toBe(true)
})

it.each([undefined, 'old-writers-stopped'])('retains an authenticated migration marker with or without quarantine evidence %#', async (evidence) => {
  const f = await fixture()
  const id = 'fixture-pending-migration'
  const record = { value: 'prior-fixture-token', source: 'fixture', receipt: 'fixture-receipt-before-migration', lifetime: 1000 }
  await writeHistory(f.file, { format: 1, status: 'migration', records: [record], migration: {
    id, fingerprint: '0'.repeat(64), ...(evidence ? { quarantineEvidence: evidence } : {}),
  } })
  expect(await f.store.state()).toMatchObject({ migrationId: id, ...(evidence ? { quarantineEvidence: evidence } : {}) })
  await expect(f.store.open('new-partition')).rejects.toThrow('machine_history_migration_required')
  await expect(f.store.sentHistory()).rejects.toThrow('machine_history_migration_required')
  await f.store.pruneSentHistory([record.receipt])
  expect(await f.store.state()).toMatchObject({ migrationId: id })
})

it('refuses malformed authenticated history and preserves the original envelope', async () => {
  const f = await fixture()
  const record = { value: 'known-test-value', receipt: 'fixture-receipt-123', source: 'test', lifetime: 1000 }
  const migration = { id: 'fixture-pending-migration', fingerprint: '0'.repeat(64) }
  const complete = { format: 1, status: 'complete', records: [] }
  for (const payload of [
    { ...complete, format: 0 }, { ...complete, records: [null] }, { ...complete, records: [record, record] },
    { ...complete, records: [{ ...record, lifetime: -1 }] }, { ...complete, migration },
    { ...complete, status: 'migration' }, { ...complete, status: 'migration', migration: { ...migration, id: 'bad' } },
    { ...complete, status: 'migration', migration: { ...migration, fingerprint: 'not-a-digest' } },
    { ...complete, status: 'migration', migration: { ...migration, quarantineEvidence: 'unsafe reference' } },
    { ...complete, records: [{ ...record, value: 'x'.repeat(1048576) }] },
  ]) {
    await writeHistory(f.file, payload)
    const stored = await readFile(f.file, 'utf8')
    await expect(f.store.open('other')).rejects.toThrow('credential_store_unavailable')
    expect(await readFile(f.file, 'utf8')).toBe(stored)
  }
})

it('refuses unsafe storage paths, disabled fences and stale generations', async () => {
  const f = await fixture()
  const readKey = async () => Buffer.alloc(32, 73)
  expect(() => new MachineConnectionStore(f.root, '../wrong', readKey)).toThrow('invalid_connection_id')
  const absent = new MachineConnectionStore(f.root, 'absent', readKey)
  expect(await absent.sentHistory()).toEqual([])
  await absent.pruneSentHistory(['absent-receipt'])
  await absent.invalidate(1, f.token('old-token', 'old'))
  await expect(absent.assertCurrent(1, 'partition')).rejects.toThrow('connection_generation_changed')
  const raw = await readFile(f.file, 'utf8')
  const original = JSON.parse(raw) as Record<string, unknown>
  for (const patch of [{ cipherGeneration: 'wrong' }, { activationId: 'bad' }, { activationId: false }]) {
    await writeFile(f.file, JSON.stringify({ ...original, ...patch }))
    await expect(f.store.state()).rejects.toThrow('credential_store_unavailable')
  }
  await writeFile(f.file, JSON.stringify({ ...original, active: false }))
  await expect(f.store.open('partition')).rejects.toThrow('connection_disabled')
  expect(await f.store.state()).toMatchObject({ active: false })
  if (process.platform !== 'win32') {
    await chmod(f.file, 0o644)
    await expect(f.store.state()).rejects.toThrow('credential_store_unavailable')
  }
})

it('reads legacy rows and fails closed if the state lock cannot be acquired', async () => {
  const f = await fixture()
  const row = JSON.parse(await readFile(f.file, 'utf8')) as Record<string, unknown>
  await writeFile(f.file, JSON.stringify({ ...row, schema: 1 }))
  expect(await f.store.state()).toMatchObject({ active: true, historyUnavailable: true })
  const lock = vi.spyOn(atomicWrite, 'withFileLock').mockRejectedValueOnce(new Error('fixture lock failure'))
  try { await expect(f.store.open('partition')).rejects.toThrow('connection_store_locked') }
  finally { lock.mockRestore() }
})

it('leaves state intact when the atomic replacement fails', async () => {
  const f = await fixture()
  const before = await readFile(f.file, 'utf8')
  const write = vi.spyOn(atomicWrite, 'writeFileAtomic').mockRejectedValueOnce(new Error('fixture write failure'))
  try {
    await expect(f.store.defer(f.generation, 'partition', Date.now() + 1000)).rejects.toThrow('credential_store_unavailable')
    expect(await readFile(f.file, 'utf8')).toBe(before)
  } finally { write.mockRestore() }
})

it('invalidates a legacy Token without losing an active operation marker', async () => {
  const f = await fixture()
  const original = JSON.parse(await readFile(f.file, 'utf8')) as Record<string, unknown>
  const activationId = 'fixture-prior-activation'
  const token = f.token('fixture-known-token', 'unused')
  delete token.issueId
  const encrypt = (value: unknown) => {
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', Buffer.alloc(32, 73), iv)
    cipher.setAAD(Buffer.from(`${f.generation}:partition`))
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()])
    return { ...original, activationId, iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'),
      ciphertext: ciphertext.toString('base64url') }
  }
  const history = { format: 1, status: 'complete', records: [] }
  await writeFile(f.file, JSON.stringify({ ...encrypt(token), tag: undefined }))
  await writeHistory(f.file, history)
  await expect(f.store.token(f.generation, 'partition')).rejects.toThrow('credential_store_unavailable')
  await writeFile(f.file, JSON.stringify(encrypt({ ...token, partition: 'wrong' })))
  await writeHistory(f.file, history)
  await expect(f.store.token(f.generation, 'partition')).rejects.toThrow('credential_store_unavailable')
  await writeFile(f.file, JSON.stringify(encrypt(token)))
  await writeHistory(f.file, history)
  expect(await f.store.token(f.generation, 'partition')).toEqual(token)
  await f.store.invalidate(f.generation, token)
  expect(await f.store.token(f.generation, 'partition')).toBeUndefined()
  expect(JSON.parse(await readFile(f.file, 'utf8'))).toMatchObject({ activationId })
  const preserved = await f.store.sentHistory()
  expect(preserved[0]?.source).toMatch(/^legacy:/u)
  await f.store.pruneSentHistory([preserved[0]!.receipt])
  expect(await f.store.sentHistory()).toEqual([])
  const malformed = { ...token, expiresAt: token.acquiredAt }
  await expect(f.store.rememberSent(f.generation, 'partition', malformed, async () => {})).rejects.toThrow('invalid_token_lifetime')
})

it('authenticates fresh empty completeness and rejects missing or truncated envelopes', async () => {
  const f = await fixture()
  const original = JSON.parse(await readFile(f.file, 'utf8'))
  expect(Boolean(original.history?.ciphertext)).toBe(true)
  for (const altered of [
    { ...original, history: undefined },
    { ...original, history: { ...original.history, ciphertext: '' } },
    { ...original, history: { ...original.history, tag: 'truncated' } },
  ]) {
    await writeFile(f.file, JSON.stringify(altered), { mode: 0o600 })
    expect((await f.store.state())!.historyUnavailable).toBe(true)
    await expect(f.store.open('partition')).rejects.toThrow('credential_store_unavailable')
    await expect(f.store.sentHistory()).rejects.toThrow('credential_store_unavailable')
  }
})
