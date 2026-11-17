/** Actual DNS, TLS, pinned sockets, bounded streams and exact-origin test transport. */
import { createServer, type Server, type ServerOptions } from 'node:https'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import * as dns from 'node:dns/promises'
import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getDefaultAutoSelectFamily, setDefaultAutoSelectFamily } from 'node:net'
import { installProxyFromEnvironment } from '@deepseek-ai/dsh-http-proxy'
import { afterAll, afterEach, beforeAll, expect, it, vi } from 'vitest'
import { assertMachineDirectRoute, createTestMachineFetch, machineFetch, machineJson, machineUrl, publicAddress } from '../src/machine-http.ts'

vi.mock('node:dns/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:dns/promises')>()
  return { ...actual, lookup: vi.fn(actual.lookup) }
})

type AllAddressLookup = (hostname: string, options: { all: true; verbatim: true }) => Promise<Array<{ address: string; family: number }>>
const lookupAll = vi.mocked(dns.lookup as AllAddressLookup)

let root: string
let ca: string
let otherCa: string
let key: Buffer
beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'mcp-machine-tls-'))
  for (const name of ['server', 'other']) {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-days', '1', '-keyout', join(root, name + '.key.pem'), '-out', join(root, name + '.cert.pem')], { stdio: 'ignore', env: {} })
  }
  ca = await readFile(join(root, 'server.cert.pem'), 'utf8')
  otherCa = await readFile(join(root, 'other.cert.pem'), 'utf8')
  key = await readFile(join(root, 'server.key.pem'))
})
afterEach(() => { vi.restoreAllMocks(); lookupAll.mockReset(); vi.unstubAllEnvs() })
afterAll(async () => { key?.fill(0); if (root) await rm(root, { recursive: true, force: true }) })

async function fixture(handler: (request: IncomingMessage, response: ServerResponse) => void, run: (fixture: {
  origin: string
  server: Server
  sockets: Set<Duplex>
  connections: () => number
  send: typeof machineFetch
}) => Promise<void>, options: ServerOptions = {}): Promise<void> {
  const server = createServer({ cert: ca, key, ...options }, handler)
  const sockets = new Set<Duplex>()
  let connections = 0
  server.on('connection', (socket) => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)) })
  server.on('secureConnection', () => { connections++ })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture_address')
  const origin = `https://localhost:${address.port}`
  try { await run({ origin, server, sockets, connections: () => connections, send: createTestMachineFetch({ origin, ca }) }) }
  finally {
    for (const socket of sockets) socket.destroy()
    await new Promise<void>(resolve => server.close(() => { resolve() }))
  }
}

it('uses real DNS and the Node all-address lookup signature, verifies TLS and opens a fresh socket for each request', async () => {
  const addresses = await dns.lookup('localhost', { all: true, order: 'verbatim' })
  expect(addresses.some(value => value.address === '127.0.0.1')).toBe(true)
  const hits: string[] = []
  await fixture((request, response) => {
    hits.push(request.url!)
    if (request.url === '/redirect') { response.writeHead(302, { location: 'https://127.0.0.1/private' }); response.end(); return }
    response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' }); response.end('{"ok":true}')
  }, async ({ origin, send, connections }) => {
    for (let i = 0; i < 2; i++) expect(await machineJson(await send(origin + '/metadata'))).toEqual({ ok: true })
    expect(connections()).toBe(2)
    const redirect = await send(origin + '/redirect', { headers: { authorization: 'Bearer local-test-marker' } })
    expect(redirect.status).toBe(302); await redirect.body?.cancel()
    expect(connections()).toBe(3)
    expect(hits).toEqual(['/metadata', '/metadata', '/redirect'])
    await expect(send(origin.replace('localhost', '127.0.0.1') + '/metadata')).rejects.toThrow('unsafe_target')
    await expect(send('https://example.com/metadata')).rejects.toThrow('unsafe_target')
    await expect(machineFetch(origin + '/metadata')).rejects.toThrow('unsafe_target')
    expect(connections()).toBe(3)
  })
})

it('rejects HTTP Host overrides before DNS, TLS or request-body transmission', async () => {
  let received = 0
  await fixture((_request, response) => { received++; response.end('unexpected') }, async ({ origin, send, connections }) => {
    await expect(send(origin + '/metadata', { method: 'POST', headers: { Host: 'different.example' },
      body: 'private-test-marker' })).rejects.toThrow('managed_authentication_header')
    expect(lookupAll).not.toHaveBeenCalled()
    expect(connections()).toBe(0)
    expect(received).toBe(0)
  })
})

it('requires its exact test origin, NODE_ENV=test and explicit CA while preserving TLS hostname verification', async () => {
  await fixture((_request, response) => { response.end('unexpected') }, async ({ origin, send }) => {
    const wrongCa = createTestMachineFetch({ origin, ca: otherCa })
    await expect(wrongCa(origin + '/metadata')).rejects.toThrow('network_failure')
    const ipOrigin = origin.replace('localhost', '127.0.0.1')
    await expect(createTestMachineFetch({ origin: ipOrigin, ca })(ipOrigin + '/metadata')).rejects.toThrow('network_failure')
    expect(() => createTestMachineFetch({ origin, ca: '' })).toThrow('test_transport_forbidden')
    expect(() => createTestMachineFetch({ origin: origin + '/', ca })).toThrow('test_transport_forbidden')
    expect(() => createTestMachineFetch({ origin: 'https://example.com', ca })).toThrow('test_transport_forbidden')
    vi.stubEnv('NODE_ENV', 'production')
    expect(() => createTestMachineFetch({ origin, ca })).toThrow('test_transport_forbidden')
    await expect(send('https://example.com/metadata')).rejects.toThrow('unsafe_target')
  })
})

it('rejects URL normalization before DNS and blocks every non-public numeric destination', async () => {
  expect(() => machineUrl('not an HTTPS URL')).toThrow('invalid_target')
  for (const value of ['http://example.com/', 'https://2130706433/', 'https://0x7f000001/', 'https://example.com/a/../b', 'https://example.com/%2e/b', 'https://example.com/?query=one', 'https://user:password@example.com/']) {
    expect(() => machineUrl(value)).toThrow('invalid_target')
    await expect(machineFetch(value)).rejects.toThrow('invalid_target')
  }
  const denied = ['0.0.0.1', '10.0.0.1', '100.64.0.1', '127.0.0.1', '127.0.1.1', '169.254.1.1', '172.16.0.1', '192.0.0.1', '192.0.2.1', '192.88.99.1', '192.168.0.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255', '::', '::1', '::ffff:8.8.8.8', '64:ff9b::1', '2001::1', '2001:db8::1', '2002::1', '3fff::1', 'fc00::1', 'fe80::1', 'ff02::1']
  for (const address of denied) expect(publicAddress(address), address).toBe(false)
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2001:4860:4860::8888']) expect(publicAddress(address), address).toBe(true)
  for (const url of ['https://192.88.99.1/', 'https://[3fff::1]/', 'https://[::ffff:808:808]/']) await expect(machineFetch(url)).rejects.toThrow('unsafe_target')
})

it('accepts insignificant whitespace in an otherwise valid OAuth document', async () => {
  const json = ' { "grants" : [ "client_credentials" , true ] } '
  expect(await machineJson(new Response(json, { headers: { 'content-type': 'application/json' } })))
    .toEqual({ grants: ['client_credentials', true] })
})

it('rejects a mixed public/private DNS answer before opening a socket', async () => {
  await fixture((_request, response) => { response.end('unexpected') }, async ({ origin, send, connections }) => {
    const lookup = lookupAll.mockResolvedValueOnce([{ address: '8.8.8.8', family: 4 }, { address: '169.254.169.254', family: 4 }])
    await expect(send(origin + '/metadata')).rejects.toThrow('unsafe_target')
    expect(lookup).toHaveBeenCalledWith('localhost', { all: true, order: 'verbatim' })
    expect(connections()).toBe(0)
  })
})

it('rejects a proxied machine route before DNS, and handles DNS with no admissible result', async () => {
  const dispose = await installProxyFromEnvironment({ get: name => name === 'HTTPS_PROXY' ? { value: 'http://proxy.example:3128' } : undefined },
    () => undefined)
  try {
    expect(() => { assertMachineDirectRoute('https://target.example') }).toThrow('proxy_egress_unsupported')
    expect(lookupAll).not.toHaveBeenCalled()
  } finally { await dispose() }
  lookupAll.mockResolvedValueOnce([])
  await expect(machineFetch('https://target.example')).rejects.toThrow('unsafe_target')
  const abort = new AbortController()
  abort.abort()
  await expect(machineFetch('https://target.example', { signal: abort.signal })).rejects.toThrow('network_failure')
  expect(lookupAll).toHaveBeenCalledTimes(1)
})

it('retains repeated response headers and accepts an empty no-content response', async () => {
  const family = getDefaultAutoSelectFamily()
  setDefaultAutoSelectFamily(false)
  try {
    await fixture((_request, response) => {
      response.writeHead(204, { 'set-cookie': ['name=a', 'other=b'] }).end()
    }, async ({ origin, send }) => {
      const response = await send(origin)
      expect(response.status).toBe(204)
      expect(response.body).toBeNull()
      expect(response.headers.getSetCookie()).toEqual(['name=a', 'other=b'])
    })
  } finally { setDefaultAutoSelectFamily(family) }
  await expect(machineJson(new Response())).rejects.toThrow('incompatible_metadata')
})

it('abandons a lookup that is cancelled synchronously before handing ownership to the waiter', async () => {
  const controller = new AbortController()
  lookupAll.mockImplementationOnce(async () => {
    controller.abort()
    return [{ address: '8.8.8.8', family: 4 }]
  })
  await expect(machineFetch('https://target.example', { signal: controller.signal })).rejects.toThrow('network_failure')
})

it('aborts a DNS wait without opening a late socket or exposing the abort reason', async () => {
  await fixture((_request, response) => { response.end('unexpected') }, async ({ origin, send, connections }) => {
    let resolve!: (addresses: Array<{ address: string; family: number }>) => void
    lookupAll.mockImplementationOnce(() => new Promise((resolveDns) => { resolve = resolveDns }))
    const controller = new AbortController()
    const pending = send(origin + '/metadata', { signal: controller.signal })
    controller.abort(new Error('private-abort-reason'))
    await expect(pending).rejects.toThrow('network_failure')
    resolve([{ address: '127.0.0.1', family: 4 }])
    await new Promise<void>(done => setImmediate(done))
    expect(connections()).toBe(0)
  })
})

it('cancels aborted and oversized request streams before transmitting any request bytes', async () => {
  await fixture((_request, response) => { response.end('unexpected') }, async ({ origin, send, connections }) => {
    let cancelled = false
    const controller = new AbortController()
    const stalled = new ReadableStream<Uint8Array>({ start(stream) { stream.enqueue(new Uint8Array([1])) }, cancel() { cancelled = true } })
    const pending = send(origin + '/upload', { method: 'POST', body: stalled, signal: controller.signal, duplex: 'half' } as RequestInit & { duplex: 'half' })
    await vi.waitFor(() => { expect(stalled.locked).toBe(true) })
    controller.abort()
    await expect(pending).rejects.toThrow('network_failure')
    expect(cancelled).toBe(true)
    let produced = 0; cancelled = false
    const oversized = new ReadableStream<Uint8Array>({
      pull(stream) { produced++; stream.enqueue(new Uint8Array(600000)) },
      cancel() { cancelled = true },
    })
    await expect(send(origin + '/upload', { method: 'POST', body: oversized, duplex: 'half' } as RequestInit & { duplex: 'half' })).rejects.toThrow('request_too_large')
    expect(produced).toBeLessThanOrEqual(3); expect(cancelled).toBe(true)
    expect(connections()).toBe(0)
  })
})

it('destroys a real HTTPS request when cancelled before response headers', async () => {
  let received!: () => void
  const arrived = new Promise<void>((resolve) => { received = resolve })
  await fixture(() => { received() }, async ({ origin, send, sockets }) => {
    const controller = new AbortController()
    const pending = send(origin + '/slow', { signal: controller.signal })
    await arrived
    controller.abort(new Error('private-abort-reason'))
    await expect(pending).rejects.toThrow('network_failure')
    await vi.waitFor(() => { expect(sockets.size).toBe(0) })
  })
})

it('applies one total deadline to a continuously streaming response and releases its socket', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
  try {
    await fixture((_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' }); response.write('{')
    }, async ({ origin, send }) => {
      const response = await send(origin + '/trickle')
      const result = expect(machineJson(response)).rejects.toThrow('incompatible_metadata')
      await vi.advanceTimersByTimeAsync(30_000)
      await result
    })
  } finally { vi.useRealTimers() }
})

it('rejects duplicate names, invalid UTF-8, BOM, non-object JSON and incorrect JSON media types over HTTPS', async () => {
  const cases: Array<{ body: string | Uint8Array; contentType?: string }> = [
    { body: '{"issuer":"one","iss\\u0075er":"two"}' },
    { body: '{"nested":{"key":1,"key":2}}' },
    { body: '{"x":"' + String.fromCharCode(0) + '"}' },
    { body: new Uint8Array([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]) },
    { body: new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]) },
    { body: '[]' }, { body: 'null' }, { body: '{"ok":true}', contentType: 'application/jsonx' },
    { body: '{"ok":true}', contentType: 'text/plain' }, { body: '{"tooLarge":"' + 'x'.repeat(65536) + '"}' },
    { body: '{"nested":' + '['.repeat(34) + '0' + ']'.repeat(34) + '}' },
  ]
  await fixture((request, response) => {
    const value = cases[Number(request.url!.slice(1))]!
    response.writeHead(200, { 'content-type': value.contentType ?? 'application/json' }); response.end(value.body)
  }, async ({ origin, send }) => {
    for (let index = 0; index < cases.length; index++) await expect(machineJson(await send(`${origin}/${index}`))).rejects.toThrow('incompatible_metadata')
  })
})
