/** Private encrypted history, receipt CAS and conservative legacy migration. No wall-clock 24-hour run. */
import { mkdtemp, readdir, readFile, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { afterEach, expect, it } from 'vitest'
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
  const { createCipheriv, createHash, randomBytes } = await import('node:crypto')
  const f = await fixture()
  const row = JSON.parse(await readFile(f.file, 'utf8'))
  const records = Array.from({ length: 256 }, (_, index) => ({ value: `private-record-${index}`, source: `source-${index}`,
    receipt: `receipt-for-record-${index}-version`, lifetime: 86400000 }))
  const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', Buffer.alloc(32, 73), iv)
  const fingerprint = createHash('sha256').update(JSON.stringify([row.generation, row.partition,
    row.cipherGeneration ?? row.generation, row.iv ?? '', row.tag ?? '', row.ciphertext ?? ''])).digest('hex')
  cipher.setAAD(Buffer.from('@deepseek-ai/dsh-mcp-client/sent-bearer-history/1:'
    + createHash('sha256').update('history').digest('hex') + ':' + fingerprint))
  const payload = { format: 1, status: 'complete', records }
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final()])
  row.history = { iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url') }
  await writeFile(f.file, JSON.stringify(row), { mode: 0o600 })
  await expect(f.store.rememberSent(f.generation, 'partition', f.token('overflow-private', 'overflow'), async () => {}))
    .rejects.toThrow('machine_secret_retention_full')
  expect((await f.store.sentHistory()).length).toBe(256)
  expect(JSON.parse(await readFile(f.file, 'utf8')).history.ciphertext === row.history.ciphertext).toBe(true)
  expect((await f.store.state())!.active).toBe(true)
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
