/** Exact known bearer retention and JSON projection, independent of field names and Token syntax. */
import { expect, it } from 'vitest'
import { MachineBearerRedactor } from '../src/machine-output.ts'

it('redacts only known values, including nested keys, without losing ordinary collision properties', () => {
  const r = new MachineBearerRedactor()
  r.remember('opaque-secret-credential', 1, 300000)
  const input = { text: 'before opaque-secret-credential after', arbitrary: { 'opaque-secret-credential': 'private', '■■■': 'ordinary' }, list: [1, 'business'] }
  const output = r.sanitize(input)
  expect(JSON.stringify(output).includes('opaque-secret-credential')).toBe(false)
  expect(Object.values(output.arbitrary)).toEqual(['private', 'ordinary'])
  expect(output.list).toEqual([1, 'business'])
  expect(input.text.includes('opaque-secret-credential')).toBe(true)
  expect(r.sanitize('unrelated-opaque-value')).toBe('unrelated-opaque-value')
})

it('does not reintroduce a short token through a replacement marker, collision suffix or array index', () => {
  const r = new MachineBearerRedactor()
  r.remember('1', 1, 300000); r.remember('[redacted]', 2, 300000)
  const result = r.sanitize({ '1': '1', '[redacted]': '[redacted]', values: ['one', 'two'] })
  const keys = Object.keys(result)
  expect(keys.some(key => key.includes('1') || key.includes('[redacted]'))).toBe(false)
  expect(result.values).toEqual(['one', 'two'])
  expect(Object.keys(result)).toHaveLength(3)
})

it('pins historical credentials through an in-flight SDK result and bounds elapsed retention by monotonic time', () => {
  let now = 0
  const r = new MachineBearerRedactor(() => now)
  r.remember('old-opaque-credential', 1, 1000)
  const release = r.begin()
  now = 100000
  r.remember('new-opaque-credential', 2, 1000)
  expect(r.sanitize('old-opaque-credential')).toBe('■■■')
  release(); release()
  expect(r.sanitize('old-opaque-credential')).toBe('old-opaque-credential')
  expect(r.sanitize('new-opaque-credential')).toBe('■■■')
  now = 200000
  r.begin()()
  expect(r.sanitize('new-opaque-credential')).toBe('new-opaque-credential')
})

it('fails closed at token and byte capacity without evicting a possibly valid credential', () => {
  const r = new MachineBearerRedactor()
  for (let i = 0; i < 256; i++) r.remember(`private-opaque-${i}`, i, 86400000)
  expect(() => r.remember('overflow', 999, 86400000)).toThrow('machine_secret_retention_full')
  expect(r.sanitize('private-opaque-0')).toBe('■■■')
  const bytes = new MachineBearerRedactor()
  for (let i = 0; i < 32; i++) bytes.remember(String.fromCharCode(65 + i) + 'a'.repeat(32767), i, 1000)
  expect(() => bytes.remember('overflow', 1, 1000)).toThrow('machine_secret_retention_full')
})

it('does not create a different known bearer at a replacement boundary', () => {
  const r = new MachineBearerRedactor()
  r.remember('long-private-value', 1, 300000)
  r.remember('x[red', 2, 300000)
  const value = r.sanitize('xlong-private-value')
  expect(value.includes('long-private-value')).toBe(false)
  expect(value.includes('x[red')).toBe(false)
})

it('also protects the exact JSON-escaped spelling used by SDK error serialization', () => {
  const token = 'private"opaque\\value'
  const r = new MachineBearerRedactor()
  r.remember(token, 1, 300000)
  const serialized = JSON.stringify({ error: token })
  const safe = r.sanitize(serialized)
  expect(safe.includes(token)).toBe(false)
  expect(safe.includes(JSON.stringify(token).slice(1, -1))).toBe(false)
})

it('masks expired complete client-auth assertions for a confirmed local identity after reconstructing the redactor', async () => {
  const { generateKeyPairSync, sign } = await import('node:crypto')
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const clientId = 'https://identity.example/client.json'
  const jwt = (header: object, claims: object) => {
    const input = Buffer.from(JSON.stringify(header)).toString('base64url') + '.' + Buffer.from(JSON.stringify(claims)).toString('base64url')
    return input + '.' + sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')
  }
  const header = { alg: 'ES256', typ: 'JWT', kid: 'did:web:identity.example#oauth' }
  const claims = { iss: clientId, sub: clientId, aud: 'https://issuer.example', iat: 1, exp: 61, jti: 'expired-client-assertion' }
  const proof = jwt(header, claims)
  const reconstructed = new MachineBearerRedactor()
  reconstructed.registerIdentity(clientId)
  const value = reconstructed.sanitize({ text: 'prefix' + proof + 'suffix', [proof]: proof })
  expect(JSON.stringify(value).includes(proof)).toBe(false)
  const unrelated = jwt({ ...header, kid: 'did:web:foreign.example#key' }, { ...claims, iss: 'https://foreign.example', sub: 'https://foreign.example' })
  const business = jwt(header, { ...claims, scope: 'business.read' })
  const pap = jwt({ ...header, typ: 'poppy-session+jwt' }, claims)
  expect(reconstructed.sanitize(unrelated)).toBe(unrelated)
  expect(reconstructed.sanitize(business)).toBe(business)
  expect(reconstructed.sanitize(pap)).toBe(pap)
  const long = jwt(header, { ...claims, exp: 601 })
  expect(reconstructed.sanitize(long)).toBe(long)
})
