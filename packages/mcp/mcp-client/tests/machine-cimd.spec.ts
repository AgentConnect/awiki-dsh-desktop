/** Real Cordis Loader, SDK, credentials and TLS fixture for CIMD. */
import { execFileSync } from 'node:child_process'
import { createPublicKey, generateKeyPairSync, verify, type JsonWebKey } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { createServer } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout } from 'node:timers/promises'
import { pathToFileURL } from 'node:url'
import { Context } from '@deepseek-ai/cordis'
import Include from '@deepseek-ai/cordis-plugin-include'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import LocalCredentials from '@deepseek-ai/dsh-credentials-local'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import McpResources from '@deepseek-ai/dsh-mcp-resources'
import SystemPrompt, { renderPrompt } from '@deepseek-ai/dsh-system-prompt'
import * as NativeToolExecutor from '@deepseek-ai/dsh-tool-executor-native'
import { executeToolFixture } from '@deepseek-ai/dsh-tool-testkit'
import Tools from '@deepseek-ai/dsh-tools'
import { expect, it, vi } from 'vitest'
import * as McpClient from '../src/index.ts'
import { discoverMachineTarget } from '../src/machine-discovery.ts'
import { createTestMachineFetch, type machineFetch } from '../src/machine-http.ts'
import { MachineConnectionStore, type MachineToken } from '../src/machine-store.ts'
import { credentialSigner, McpSigningProviderRegistry, signingProvider } from '../src/signing-provider.ts'

const wire = vi.hoisted(() => ({ send: undefined as typeof machineFetch | undefined }))
vi.mock('../src/machine-http.ts', async (importOriginal) => {
  const source = await importOriginal<typeof import('../src/machine-http.ts')>()
  return { ...source, machineFetch: (...args: Parameters<typeof machineFetch>) => {
    if (!wire.send) throw new Error('Missing isolated TLS test fixture')
    return wire.send(...args)
  } }
})

async function body(request: IncomingMessage): Promise<string> {
  let text = ''
  for await (const chunk of request) text += String(chunk)
  return text
}

function json(response: ServerResponse, value: object): void {
  response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(value))
}

it.each(['modern', 'legacy'])('loads a %s machine connection through challenge and OIDC and retains operation limits', async (era) => {
  const root = await mkdtemp(join(tmpdir(), 'mcp-cimd-'))
  const context = new Context()
  const key = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  let clientKey = key()
  let origin = ''
  let issued = 0
  let challenges = 0
  let wellKnown = 0
  let oidc = 0
  let jwks = 0
  let tokenAttempts = 0
  let throttle: Headers | undefined
  let nextToolResponse: ((response: ServerResponse, id: number) => void) | undefined
  let nextListing: ((reply: () => void) => void) | undefined
  let nextRead: ((reply: () => void) => void) | undefined
  let readError = false
  let instructions = 'fixture server instructions'
  let toolCalls = 0
  const cancellationNotice = Promise.withResolvers<unknown>()
  const failures: unknown[] = []
  const receivedAssertions = new Set<string>()
  const handle = async (request: IncomingMessage, response: ServerResponse) => {
    const issuer = `${origin}/issuer`
    const client = `${origin}/client.json`
    const resource = `${origin}/mcp`
    switch (request.url) {
      case '/resource-metadata': return json(response, { resource, authorization_servers: [issuer] })
      case '/.well-known/oauth-protected-resource/mcp': wellKnown++; return void response.writeHead(404).end()
      case '/issuer/.well-known/openid-configuration':
        oidc++
        return json(response, { issuer, token_endpoint: `${origin}/token`, client_id_metadata_document_supported: true,
          grant_types_supported: ['client_credentials'], token_endpoint_auth_methods_supported: ['private_key_jwt'],
          token_endpoint_auth_signing_alg_values_supported: ['ES256'] })
      case '/client.json': return json(response, { client_id: client, jwks_uri: `${origin}/jwks` })
      case '/jwks':
        jwks++
        return json(response, { keys: [{ ...clientKey.publicKey.export({ format: 'jwk' }), kid: 'current-key' }] })
      case '/token': {
        tokenAttempts++
        if (throttle) return void response.writeHead(429, Object.fromEntries(throttle)).end()
        const form = new URLSearchParams(await body(request))
        expect(form.get('grant_type')).toBe('client_credentials')
        expect(form.get('client_id')).toBe(client)
        expect(form.get('resource')).toBe(resource)
        const publication = await (await wire.send!(client)).json() as { jwks_uri: string }
        const publicKeys = (await (await wire.send!(publication.jwks_uri)).json()) as { keys: JsonWebKey[] }
        const [header, claims, signature] = form.get('client_assertion')!.split('.')
        expect(JSON.parse(Buffer.from(header!, 'base64url').toString())).toEqual({ alg: 'ES256', kid: 'current-key', typ: 'client-authentication+jwt' })
        const payload = JSON.parse(Buffer.from(claims!, 'base64url').toString()) as { jti: string }
        expect(payload).toMatchObject({ iss: client, sub: client, aud: issuer })
        expect(receivedAssertions.has(payload.jti)).toBe(false)
        receivedAssertions.add(payload.jti)
        expect(verify('sha256', Buffer.from(`${header}.${claims}`), {
          key: createPublicKey({ key: publicKeys.keys[0]!, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
        }, Buffer.from(signature!, 'base64url'))).toBe(true)
        return json(response, { access_token: `private-token-${++issued}`, token_type: 'Bearer', expires_in: issued === 1 ? 1 : 600, scope: 'catalog.read' })
      }
      case '/mcp': {
        if (!request.headers.authorization) {
          expect(request.method).toBe('POST')
          expect(JSON.parse(await body(request))).toMatchObject({ method: 'server/discover' })
          challenges++
          return void response.writeHead(401, { 'www-authenticate': `Bearer resource_metadata="${origin}/resource-metadata"` }).end()
        }
        if (request.method === 'GET') return void response.writeHead(405).end()
        const rpc = JSON.parse(await body(request)) as { method: string; id: number; params?: { requestId?: number } }
        const result = (value: object) => json(response, { jsonrpc: '2.0', id: rpc.id,
          result: { resultType: 'complete', ttlMs: 0, cacheScope: 'private', ...value } })
        switch (rpc.method) {
          case 'server/discover': return era === 'modern'
            ? result({ supportedVersions: ['2026-07-28'], capabilities: { tools: {}, resources: {} }, instructions })
            : json(response, { jsonrpc: '2.0', id: rpc.id, error: { code: -32601, message: 'Method not found' } })
          case 'initialize': return result({ protocolVersion: '2025-11-25', capabilities: { tools: {}, resources: {} }, instructions,
            serverInfo: { name: 'fixture', version: '1' } })
          case 'notifications/initialized': return void response.writeHead(202).end()
          case 'notifications/cancelled': {
            cancellationNotice.resolve(rpc.params?.requestId)
            return void response.writeHead(202).end()
          }
          case 'tools/list': {
            const reply = () => result({ tools: [{ name: 'catalog', description: 'Read one catalog entry', inputSchema: { type: 'object' } }] })
            const listing = nextListing
            nextListing = undefined
            if (listing) listing(reply)
            else reply()
            return
          }
          case 'tools/call': {
            toolCalls++
            const reply = nextToolResponse
            nextToolResponse = undefined
            if (reply) return reply(response, rpc.id)
            return result({ content: [{ type: 'text', text: `catalog entry ${request.headers.authorization}` }] })
          }
          case 'resources/read': {
            if (readError) return json(response, { jsonrpc: '2.0', id: rpc.id,
              error: { code: -32603, message: `fixture resource refusal ${request.headers.authorization}` } })
            const read = nextRead
            nextRead = undefined
            const text = read ? 'stale resource result' : 'current resource result'
            const reply = () => response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: {
              resultType: 'complete', ttlMs: 0, cacheScope: 'private', contents: [{ uri: 'test://resource', text }],
            } }))
            response.writeHead(200, { 'content-type': 'application/json', 'x-fixture-held': 'yes' })
            if (read) { response.flushHeaders(); read(reply) }
            else reply()
            return
          }
          default: throw new Error(`Unexpected test RPC method ${rpc.method}`)
        }
      }
      default: response.writeHead(404).end()
    }
  }
  const certPath = join(root, 'cert.pem')
  const keyPath = join(root, 'key.pem')
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost', '-days', '1', '-keyout', keyPath, '-out', certPath], { stdio: 'ignore' })
  const [cert, tlsKey] = await Promise.all([readFile(certPath, 'utf8'), readFile(keyPath)])
  const server = createServer({ cert, key: tlsKey }, (request, response) => {
    void handle(request, response).catch((error) => { failures.push(error); response.writeHead(500).end() })
  })
  try {
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('No fixture address')
    origin = `https://localhost:${address.port}`
    const pinned = createTestMachineFetch({ origin, ca: cert })
    let heldHeaders = Promise.withResolvers<undefined>()
    wire.send = async (...args) => {
      const response = await pinned(...args)
      if (response.headers.has('x-fixture-held')) heldHeaders.resolve(undefined)
      return response
    }
    const credential = { clientId: `${origin}/client.json`, keyId: 'current-key', issuer: `${origin}/issuer`, resource: `${origin}/mcp` }
    const registry = new McpSigningProviderRegistry(context)
    let releaseSigner = era === 'legacy' ? registry.register('fixture', credentialSigner(credential)) : undefined
    const config = {
      transport: 'streamable-http', serverName: 'cimd', url: `${origin}/mcp`, failOnStartupError: true,
      reconnect: { enabled: false }, authentication: { mode: 'cimd-client-credentials', connectionId: 'cimd-test', credentialRef: 'CIMD_SIGNING_KEY',
        ...(era === 'modern' ? { issuer: `${origin}/issuer` } : {}),
        ...(era === 'legacy' ? { provider: 'fixture' } : { provider: 'credentials', credential }),
        stateRoot: join(root, 'state'), encryptionKeyRef: 'CIMD_STORAGE_KEY', requestedScopes: ['catalog.read'] },
    }
    await context.plugin(SystemPrompt)
    await context.plugin(Tools)
    await context.plugin(NativeToolExecutor)
    await context.plugin(McpResources)
    await context.plugin(LocalCredentials, { dshHome: root, watch: false })
    const credentials = context.get('credentials')!
    const putKey = () => credentials.set(credentialRef('CIMD_SIGNING_KEY'), clientKey.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString())
    await putKey()
    await credentials.set(credentialRef('CIMD_STORAGE_KEY'), Buffer.alloc(32, 197).toString('base64url'))
    await context.plugin(Loader)
    context.loader.builtins.include = Include
    const unexpectedModuleOperation = (): never => { throw new Error('Unexpected fixture Loader module operation') }
    context.loader.internal = { version: 'v2', import: async () => McpClient, loadCache: new Map(),
      register: unexpectedModuleOperation, getOrCreateModuleJob: unexpectedModuleOperation,
      resolveSync: unexpectedModuleOperation, load: unexpectedModuleOperation }
    let includes = 0
    const include = async () => {
      const file = join(root, `cordis-${++includes}.yml`)
      await writeFile(file, `- name: '@deepseek-ai/dsh-mcp-client'\n  config: ${JSON.stringify(config)}\n`)
      return context.loader.create({ name: 'cordis:include', config: { path: pathToFileURL(file).href } })
    }
    await include()
    await context.loader.await()
    expect(failures).toEqual([])
    expect({ challenges, wellKnown, oidc, jwks, issued }).toEqual({ challenges: 1, wellKnown: 0, oidc: 1, jwks: 1, issued: 1 })
    const callRaw = (signal = new AbortController().signal) => executeToolFixture(context, { name: 'mcp__cimd__catalog', arguments: {},
      callId: ToolCallId('cimd-fixture-call'), signal })
    const call = async () => {
      const output = await callRaw()
      expect(output.isError).toBe(false)
      expect(JSON.stringify(output)).toContain('catalog entry')
      expect(JSON.stringify(output)).not.toContain('private-token-')
    }
    await call()
    await setTimeout(1100)
    await call()
    expect(issued).toBe(2)
    clientKey = key()
    await putKey()
    await call()
    expect({ challenges, oidc, jwks, issued }).toEqual({ challenges: 1, oidc: 1, jwks: 3, issued: 3 })

    const held = Promise.withResolvers<() => void>()
    nextToolResponse = (response, id) => {
      response.writeHead(200, { 'content-type': 'text/event-stream', 'x-fixture-held': 'yes' }).flushHeaders()
      held.resolve(() => response.end(`data: ${JSON.stringify({ jsonrpc: '2.0', id,
        result: { resultType: 'complete', content: [{ type: 'text', text: 'stale fixture result' }] } })}\n\n`))
    }
    const oldRequest = callRaw()
    await heldHeaders.promise
    try {
      if (releaseSigner) {
        await releaseSigner()
        releaseSigner = registry.register('fixture', credentialSigner(credential))
      } else {
        clientKey = key()
        await putKey()
      }
      await call()
    } finally { (await held.promise)() }
    const stale = await oldRequest
    expect(stale.isError).toBe(true)
    expect(JSON.stringify(stale)).not.toContain('stale fixture result')

    heldHeaders = Promise.withResolvers<undefined>()
    const resource = Promise.withResolvers<() => void>()
    nextRead = resource.resolve
    const oldResource = executeToolFixture(context, { name: 'read_mcp_resource', arguments: { server: 'cimd', uri: 'test://resource' },
      callId: ToolCallId('cimd-resource'), signal: new AbortController().signal })
    await heldHeaders.promise
    try {
      clientKey = key()
      await putKey()
      await call()
    } finally { (await resource.promise)() }
    const staleResource = await oldResource
    expect(staleResource.isError).toBe(true)
    expect(JSON.stringify(staleResource)).not.toContain('stale resource result')
    readError = true
    const refusedResource = await executeToolFixture(context, { name: 'read_mcp_resource', arguments: { server: 'cimd', uri: 'test://resource' },
      callId: ToolCallId('cimd-resource-refused'), signal: new AbortController().signal })
    expect(refusedResource.isError).toBe(true)
    expect(JSON.stringify(refusedResource)).toContain('fixture resource refusal')
    expect(JSON.stringify(refusedResource)).not.toContain('private-token-')
    readError = false
    const currentResource = await executeToolFixture(context, { name: 'read_mcp_resource',
      arguments: { server: 'cimd', uri: 'test://resource' }, callId: ToolCallId('cimd-resource-recovered'), signal: new AbortController().signal })
    expect(currentResource.isError).toBe(false)
    expect(JSON.stringify(currentResource)).toContain('current resource result')

    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    for (const format of ['json', 'sse']) {
      const arrived = Promise.withResolvers<() => void>()
      nextToolResponse = (response, id) => {
        const result = { jsonrpc: '2.0', id, result: { resultType: 'complete', content: [{ type: 'text', text: 'slow fixture result' }] } }
        if (format === 'sse') {
          response.writeHead(200, { 'content-type': 'text/event-stream' })
          response.write('data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":1}}\n\n')
        }
        arrived.resolve(() => {
          if (format === 'sse') response.end(`data: ${JSON.stringify(result)}\n\n`)
          else json(response, result)
        })
      }
      const before = toolCalls
      const pending = callRaw()
      const finish = await arrived.promise
      await vi.advanceTimersByTimeAsync(40_000)
      finish()
      const result = await pending
      expect(result.isError).toBe(false)
      expect(JSON.stringify(result)).toContain('slow fixture result')
      expect(toolCalls).toBe(before + 1)
    }
    for (const [header, wait] of [['2', 2000], [new Date(Date.now() + 8000).toUTCString(), 6000], [null, 1000], ['invalid', 1000]] as const) {
      clientKey = key()
      await putKey()
      throttle = new Headers(header === null ? {} : { 'retry-after': header })
      const before = tokenAttempts
      expect((await callRaw()).isError).toBe(true)
      expect(tokenAttempts).toBe(before + 1)
      throttle = undefined
      expect((await callRaw()).isError).toBe(true)
      expect(tokenAttempts).toBe(before + 1)
      await vi.advanceTimersByTimeAsync(wait)
      await call()
      expect(tokenAttempts).toBe(before + 2)
    }

    const arrived = Promise.withResolvers<undefined>()
    const closed = Promise.withResolvers<undefined>()
    let cancelledId: number | undefined
    nextToolResponse = (response, id) => {
      cancelledId = id
      response.once('close', () => closed.resolve(undefined))
      response.writeHead(200, { 'content-type': 'text/event-stream' }).flushHeaders()
      arrived.resolve(undefined)
    }
    const cancellation = new AbortController()
    const cancelled = callRaw(cancellation.signal)
    await arrived.promise
    cancellation.abort()
    expect((await cancelled).isError).toBe(true)
    if (era === 'legacy') {
      expect(await cancellationNotice.promise).toBe(cancelledId)
      expect(await Promise.race([closed.promise.then(() => true), setTimeout(200, false)])).toBe(true)
    }
    await closed.promise

    const installed = () => [...context.loader.entries()].filter(entry => entry.options.name === '@deepseek-ai/dsh-mcp-client').at(-1)?.fiber
    await installed()!.dispose()
    instructions = 'stale startup instructions'
    const listing = Promise.withResolvers<() => void>()
    nextListing = listing.resolve
    const mounting = include()
    const finishListing = await listing.promise
    const startupFiber = installed()!
    McpClient.connectionStatusOf(startupFiber)?.onChange(() => { throw new Error('fixture status observer') })
    clientKey = key()
    await putKey()
    finishListing()
    await mounting
    await context.loader.await()
    expect(context.tools.schemas().some(tool => tool.name === 'mcp__cimd__catalog')).toBe(false)
    expect(renderPrompt(await context.systemPrompt.assemble())).not.toContain('stale startup instructions')
    await installed()!.dispose()
    instructions = 'current startup instructions'
    await include()
    await context.loader.await()
    await installed()!.await()
    const prompt = renderPrompt(await context.systemPrompt.assemble())
    expect(prompt).toContain('current startup instructions')
    expect(prompt).not.toContain('stale startup instructions')
    expect(failures).toEqual([])
  } finally {
    vi.useRealTimers()
    await context.fiber.dispose()
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
    wire.send = undefined
    tlsKey.fill(0)
    await rm(root, { recursive: true, force: true })
  }
}, 15000)

it('a delayed unauthorized response preserves the concurrently replaced Token', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mcp-cimd-cas-'))
  try {
    const store = new MachineConnectionStore(root, 'cas-test', async () => Buffer.alloc(32, 251))
    const generation = await store.open('partition')
    const old = { token: 'first-issued', issueId: 'first', partition: 'partition', scopes: ['catalog.read'],
      acquiredAt: Date.now(), expiresAt: Date.now() + 60000 } satisfies MachineToken
    await store.commit(generation, old)
    const replacement = { ...old, issueId: 'new', token: 'second-issued' }
    await store.commit(generation, replacement)
    await store.invalidate(generation, old)
    expect(await store.token(generation, 'partition')).toEqual(replacement)
    await store.invalidate(generation, replacement)
    expect(await store.token(generation, 'partition')).toBeUndefined()
  } finally { await rm(root, { recursive: true, force: true }) }
})

it('names a signer once per Host and retires its generation when its effect is released', async () => {
  const context = new Context()
  const implementation = { async bind() { throw new Error('Fixture provider is not expected to sign') } }
  const registry = new McpSigningProviderRegistry(context)
  try {
    const release = registry.register('alternate', implementation)
    const first = signingProvider(context, 'alternate')
    expect(first?.provider).toBe(implementation)
    expect(() => registry.register('alternate', implementation)).toThrow()
    await release()
    expect(signingProvider(context, 'alternate')).toBeUndefined()
    const replacement = registry.register('alternate', implementation)
    expect(signingProvider(context, 'alternate')?.generation).not.toBe(first?.generation)
    await replacement()
  } finally { await context.fiber.dispose() }
})

it('validates an external signer configuration without built-in credential fields', () => {
  const config = McpClient.Config({ transport: 'streamable-http', url: 'https://resource.example/mcp', serverName: 'alternate',
    authentication: { mode: 'cimd-client-credentials', connectionId: 'alternate', provider: 'alternate', credentialRef: 'registered',
      requestedScopes: ['catalog.read'], stateRoot: '/tmp/fixture', encryptionKeyRef: 'MCP_STATE_KEY' } })
  expect(config).toMatchObject({ authentication: { provider: 'alternate', credentialRef: 'registered' } })
  expect(config.transport === 'streamable-http' && config.authentication).not.toHaveProperty('credential')
})

it.each([
  { selected: 'https://issuer.example/other', metadata: 'https://issuer.example/tenant', reads: 0 },
  { selected: 'https://issuer.example/tenant', metadata: 'https://issuer.example/tenant/', reads: 1 },
])('refuses a different configured or returned issuer before any Token request', async ({ selected, metadata, reads }) => {
  const resource = 'https://resource.example/mcp'
  const issuer = 'https://issuer.example/tenant'
  let asReads = 0
  const send: typeof machineFetch = async (input, init) => {
    const request = new Request(input, init)
    if (request.url === resource) return new Response(null, { status: 401,
      headers: { 'www-authenticate': 'Bearer resource_metadata="https://resource.example/prm"' } })
    if (request.url === 'https://resource.example/prm') return Response.json({ resource, authorization_servers: [issuer] })
    expect(request.url).toBe('https://issuer.example/.well-known/oauth-authorization-server/tenant')
    asReads++
    return Response.json({ issuer: metadata, token_endpoint: 'https://issuer.example/token', client_id_metadata_document_supported: true,
      grant_types_supported: ['client_credentials'], token_endpoint_auth_methods_supported: ['private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported: ['ES256'] })
  }
  await expect(discoverMachineTarget(resource, selected, send, new AbortController().signal)).rejects.toMatchObject({ code: 'MCP_MACHINE_DISCOVERY' })
  expect(asReads).toBe(reads)
})
