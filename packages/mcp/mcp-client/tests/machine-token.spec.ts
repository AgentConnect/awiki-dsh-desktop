import { createHash } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { expect, it, vi } from 'vitest'
import { MachineAuthenticationSession } from '../src/machine-auth.ts'
import type { machineFetch } from '../src/machine-http.ts'
import { McpSigningProviderRegistry } from '../src/signing-provider.ts'
import type { McpSigningProvider } from '../src/machine-types.ts'
import { MachineConnectionStore } from '../src/machine-store.ts'

const issuer = 'https://auth.example'
const resource = 'https://resource.example/mcp'
const valid = { access_token: 'fixture-token', token_type: 'Bearer', expires_in: 60 }
const identity = { clientId: 'https://identity.example/client.json', keyId: 'fixture', algorithm: 'ES256' as const,
  policyVersion: '1', keyVersion: '1' }

interface FixtureOptions {
  provider?: McpSigningProvider | null
  storageKey?: string
  resourceReply?: () => Promise<Response>
  beforeResource?: () => void
  seedLegacy?: boolean
}

async function withSession(reply: () => Response | Promise<Response>,
  use: (
    session: MachineAuthenticationSession, requests: string[], register: (provider: McpSigningProvider) => Promise<void>,
  ) => Promise<void>,
  options: FixtureOptions = {}) {
  const ctx = new Context()
  const stateRoot = await mkdtemp(join(tmpdir(), 'mcp-token-test-'))
  const controller = new AbortController()
  const requests: string[] = []
  let discovering = true
  const send: typeof machineFetch = async (input, init, check) => {
    const request = new Request(input, init)
    requests.push(request.url)
    if (request.url === resource && !discovering) options.beforeResource?.()
    await check?.()
    if (request.url === resource && discovering) {
      discovering = false
      return new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer resource_metadata="https://resource.example/prm"' } })
    }
    if (request.url === 'https://resource.example/prm') return Response.json({ resource, authorization_servers: [issuer] })
    if (request.url === `${issuer}/.well-known/oauth-authorization-server`) return Response.json({
      issuer, token_endpoint: `${issuer}/token`, client_id_metadata_document_supported: true,
      grant_types_supported: ['client_credentials'], token_endpoint_auth_methods_supported: ['private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported: ['ES256'],
    })
    if (request.url === `${issuer}/token`) return reply()
    expect(request.url).toBe(resource)
    expect(request.headers.get('authorization')).toBe('Bearer fixture-token')
    return options.resourceReply?.() ?? Response.json({ ok: true })
  }
  const registry = new McpSigningProviderRegistry(ctx)
  const provider: McpSigningProvider = { async bind() {
    return {
      identity,
      assertActive: () => Promise.resolve(), signClientAssertion: () => Promise.resolve('test-client-assertion'), dispose() {},
    }
  } }
  let release = options.provider === null ? undefined : registry.register('fixture', options.provider ?? provider)
  const register = async (next: McpSigningProvider) => {
    await release?.()
    release = registry.register('fixture', next)
  }
  const credentials = { resolve: async () => ({
    value: options.storageKey ?? Buffer.alloc(32, 226).toString('base64url'), source: 'file' as const,
  }) }
  ctx.provide('credentials', credentials)
  const session = new MachineAuthenticationSession(ctx, { mode: 'cimd-client-credentials', provider: 'fixture', connectionId: 'one',
    credentialRef: 'MCP_SIGNER', requestedScopes: ['tool.read'], stateRoot, encryptionKeyRef: 'MCP_KEY' }, resource, controller.signal, send)
  try {
    if (options.seedLegacy) {
      const file = `${createHash('sha256').update('one').digest('hex')}.json`
      await writeFile(join(stateRoot, file), JSON.stringify({ schema: 1, active: true, generation: 1, partition: 'old' }), { mode: 0o600 })
    }
    await use(session, requests, register)
  }
  finally {
    controller.abort()
    await ctx.fiber.dispose()
    await rm(stateRoot, { recursive: true, force: true })
  }
}

it.each([
  { access_token: '' }, { access_token: false }, { token_type: '' }, { token_type: 2 }, { refresh_token: 'unexpected' },
  { expires_in: null }, { expires_in: 0 }, { expires_in: 2.1 }, { expires_in: 8600000 },
  { scope: ['tool.read'] }, { scope: 'other.read' },
])('rejects malformed or expanded Token claims without forwarding a resource request %#', async (changed) => {
  await withSession(() => Response.json({ ...valid, ...changed }), async (session, requests) => {
    await expect(session.fetch(resource)).rejects.toMatchObject({ code: 'MCP_MACHINE_TOKEN_FAILED' })
    expect(requests.filter(value => value === resource)).toHaveLength(1)
  })
})

it('refuses to send when inherited state needs recovery, the signer returns invalid identity, or signing fails', async () => {
  for (const [options, code] of [
    [{ seedLegacy: true }, 'MCP_MACHINE_STATE_UNAVAILABLE'],
    [{ provider: { bind: async () => ({ identity: { ...identity, keyId: '' }, assertActive: async () => {},
      signClientAssertion: async () => 'unused', dispose() {} }) } }, 'MCP_MACHINE_SIGNER_UNAVAILABLE'],
    [{ provider: { bind: async () => ({ identity, assertActive: async () => {},
      signClientAssertion: async () => { throw new Error('fixture signer refused') }, dispose() {} }) } }, 'MCP_MACHINE_SIGNER_UNAVAILABLE'],
  ] satisfies [FixtureOptions, string][]) {
    await withSession(() => Response.json(valid), async (session, requests) => {
      await expect(session.fetch(resource)).rejects.toMatchObject({ code })
      expect(requests).not.toContain(`${issuer}/token`)
    }, options)
  }
})

it('discards a lease from a provider replaced during binding', async () => {
  const started = Promise.withResolvers<undefined>()
  const proceed = Promise.withResolvers<undefined>()
  const dispose = vi.fn()
  const lease = { identity, assertActive: async () => {}, signClientAssertion: async () => 'fixture', dispose }
  const provider = { async bind() { started.resolve(undefined); await proceed.promise; return lease } }
  await withSession(() => Response.json(valid), async (session, requests, register) => {
    const outcome = expect(session.fetch(resource)).rejects.toThrow('signing provider was replaced')
    await started.promise
    try { await register({ bind: async () => lease }) }
    finally { proceed.resolve(undefined) }
    await outcome
    expect(dispose).toHaveBeenCalledTimes(1)
    expect(requests).not.toContain(`${issuer}/token`)
  }, { provider })
})

it('refuses a Token that expires during physical request preparation', async () => {
  await withSession(() => Response.json(valid), async (session) => {
    try { await expect(session.fetch(resource)).rejects.toThrow('expired before dispatch') }
    finally { vi.useRealTimers() }
  }, { beforeResource: () => { vi.setSystemTime(Date.now() + 61_000) } })
})

it('closes a late response when the request binding changes before response headers', async () => {
  const started = Promise.withResolvers<undefined>()
  const reply = Promise.withResolvers<Response>()
  const cancel = vi.fn()
  const replacement = { bind: async () => ({ identity, assertActive: async () => {},
    signClientAssertion: async () => 'fixture', dispose() {} }) }
  await withSession(() => Response.json(valid), async (session, _requests, register) => {
    const result = expect(session.fetch(resource)).rejects.toMatchObject({ code: 'MCP_MACHINE_SIGNER_UNAVAILABLE' })
    await started.promise
    try { await register(replacement) }
    finally { reply.resolve(new Response(new ReadableStream({ cancel }))) }
    await result
    expect(cancel).toHaveBeenCalledTimes(1)
  }, { resourceReply: () => { started.resolve(undefined); return reply.promise } })
})

it.each([true, false])('adopts the newer binding when an older lease check fails late (replacement ready: %s)', async (ready) => {
  let bindings = 0
  let expired = false
  let pendingCheck = false
  const started = Promise.withResolvers<undefined>()
  const proceed = Promise.withResolvers<undefined>()
  const rebinding = Promise.withResolvers<undefined>()
  const finishBinding = Promise.withResolvers<undefined>()
  const provider: McpSigningProvider = { async bind() {
    const current = ++bindings
    if (current === 2 && !ready) { rebinding.resolve(undefined); await finishBinding.promise }
    return { identity: { ...identity, keyVersion: String(current) },
      async assertActive() {
        if (current !== 1 || !expired) return
        if (!pendingCheck) { pendingCheck = true; started.resolve(undefined); await proceed.promise }
        throw new Error('fixture key has changed')
      },
      signClientAssertion: async () => 'fixture', dispose() {},
    }
  } }
  await withSession(() => Response.json(valid), async (session, requests) => {
    await (await session.fetch(resource)).body?.cancel()
    expired = true
    const slow = session.fetch(resource)
    await started.promise
    const replacement = session.fetch(resource)
    if (ready) {
      try { await (await replacement).body?.cancel() }
      finally { proceed.resolve(undefined) }
    } else {
      await rebinding.promise
      proceed.resolve(undefined)
      await new Promise(resolve => setImmediate(resolve))
      finishBinding.resolve(undefined)
      await (await replacement).body?.cancel()
    }
    await (await slow).body?.cancel()
    expect(bindings).toBe(2)
    expect(requests.filter(url => url === `${issuer}/token`)).toHaveLength(2)
  }, { provider })
})

it('keeps the new single-flight exchange after the replaced binding settles', async () => {
  const started = [Promise.withResolvers<undefined>(), Promise.withResolvers<undefined>()]
  const bodies = [Promise.withResolvers<Response>(), Promise.withResolvers<Response>()]
  const provider = { bind: async () => ({ identity, assertActive: async () => {}, signClientAssertion: async () => 'fixture', dispose() {} }) }
  let attempts = 0
  await withSession(() => {
    const next = attempts++
    started[next]!.resolve(undefined)
    return bodies[next]!.promise
  }, async (session, _requests, register) => {
    const stale = expect(session.fetch(resource)).rejects.toThrow('connection_generation_changed')
    await started[0]!.promise
    await register(provider)
    const replacement = session.fetch(resource)
    await started[1]!.promise
    bodies[0]!.resolve(Response.json(valid))
    await stale
    bodies[1]!.resolve(Response.json(valid))
    expect(await (await replacement).json()).toEqual({ ok: true })
    expect(attempts).toBe(2)
  }, { provider })
})

it('holds concurrent sends behind a single Token exchange', async () => {
  const started = Promise.withResolvers<undefined>()
  const provide = Promise.withResolvers<Response>()
  const concurrent = Promise.withResolvers<undefined>()
  const retryAt = MachineConnectionStore.prototype.retryAt
  let readers = 0
  const observed = vi.spyOn(MachineConnectionStore.prototype, 'retryAt').mockImplementation(async function (this: MachineConnectionStore, ...args) {
    const deadline = await retryAt.apply(this, args)
    if (++readers === 2) concurrent.resolve(undefined)
    return deadline
  })
  try {
    await withSession(() => { started.resolve(undefined); return provide.promise }, async (session, requests) => {
      const pending = session.fetch(resource)
      await started.promise
      const second = session.fetch(resource)
      await concurrent.promise
      provide.resolve(Response.json(valid))
      const results = await Promise.all([pending, second])
      for (const response of results) expect(await response.json()).toEqual({ ok: true })
      expect(requests.filter(url => url === `${issuer}/token`)).toHaveLength(1)
    })
  } finally { observed.mockRestore(); provide.resolve(Response.error()) }
})

it('invalidates a refused Token and leaves the next independent call to acquire another', async () => {
  let responses = 0
  await withSession(() => Response.json(valid), async (session, requests) => {
    await expect(session.fetch(resource)).rejects.toMatchObject({ code: 'MCP_REQUEST_FAILED' })
    expect(requests.filter(url => url === `${issuer}/token`)).toHaveLength(1)
    expect(await (await session.fetch(resource)).json()).toEqual({ ok: true })
    expect(requests.filter(url => url === `${issuer}/token`)).toHaveLength(2)
  }, { resourceReply: async () => ++responses === 1 ? new Response('rejected', { status: 401 }) : Response.json({ ok: true }) })
})

it('fails before following a redirect or using a rejected or expired Token', async () => {
  await withSession(() => Response.json(valid), async (session) => {
    await expect(session.fetch(resource)).rejects.toThrow('cannot follow redirects')
  }, { resourceReply: async () => new Response('moved', { status: 302, headers: { location: 'https://elsewhere.example' } }) })
  await withSession(() => new Response('unavailable', { status: 503 }), async (session) => {
    await expect(session.fetch(resource)).rejects.toThrow('returned HTTP 503')
  })
  await withSession(() => {
    vi.setSystemTime(Date.now() + 61_000)
    return Response.json(valid)
  }, async (session) => {
    try { await expect(session.fetch(resource)).rejects.toThrow('expired before it could be used') }
    finally { vi.useRealTimers() }
  })
})

it('rejects a missing or refused signer and missing storage key without an authenticated request', async () => {
  for (const [options, code] of [
    [{ provider: null }, 'MCP_MACHINE_SIGNER_UNAVAILABLE'],
    [{ provider: { bind: async () => { throw new Error('test synthetic refusal') } } }, 'MCP_MACHINE_SIGNER_UNAVAILABLE'],
    [{ storageKey: 'invalid-fixture-key' }, 'MCP_CREDENTIAL_NOT_FOUND'],
  ] satisfies [FixtureOptions, string][]) {
    await withSession(() => Response.json(valid), async (session, requests) => {
      await expect(session.fetch(resource)).rejects.toMatchObject({ code })
      expect(requests).not.toContain(`${issuer}/token`)
    }, options)
  }
})

it('accepts an omitted scope and rejects Host-owned request headers before Token exchange', async () => {
  await withSession(() => Response.json(valid), async (session, requests) => {
    await expect(session.fetch(resource, { headers: { cookie: 'fixture' } })).rejects.toMatchObject({ code: 'MCP_MACHINE_CONFIGURATION' })
    await expect(session.fetch('https://resource.example/other')).rejects.toMatchObject({ code: 'MCP_MACHINE_CONFIGURATION' })
    expect(requests).not.toContain(`${issuer}/token`)
    expect(await (await session.fetch(resource)).json()).toEqual({ ok: true })
  })
})
