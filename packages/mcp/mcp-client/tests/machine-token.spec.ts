import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { expect, it } from 'vitest'
import { MachineAuthenticationSession } from '../src/machine-auth.ts'
import type { machineFetch } from '../src/machine-http.ts'
import { McpSigningProviderRegistry } from '../src/signing-provider.ts'

const issuer = 'https://auth.example'
const resource = 'https://resource.example/mcp'
const valid = { access_token: 'fixture-token', token_type: 'Bearer', expires_in: 60 }

async function withSession(reply: () => Response, use: (session: MachineAuthenticationSession, requests: string[]) => Promise<void>) {
  const ctx = new Context()
  const stateRoot = await mkdtemp(join(tmpdir(), 'mcp-token-test-'))
  const controller = new AbortController()
  const requests: string[] = []
  let discovering = true
  const send: typeof machineFetch = async (input, init, check) => {
    const request = new Request(input, init)
    requests.push(request.url)
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
    return Response.json({ ok: true })
  }
  const registry = new McpSigningProviderRegistry(ctx)
  registry.register('fixture', { async bind() {
    return {
      identity: { clientId: 'https://identity.example/client.json', keyId: 'fixture', algorithm: 'ES256', policyVersion: '1', keyVersion: '1' },
      assertActive: () => Promise.resolve(), signClientAssertion: () => Promise.resolve('test-client-assertion'), dispose() {},
    }
  } })
  const credentials = { resolve: async () => ({ value: Buffer.alloc(32, 226).toString('base64url'), source: 'file' as const }) }
  ctx.provide('credentials', credentials)
  const session = new MachineAuthenticationSession(ctx, { mode: 'cimd-client-credentials', provider: 'fixture', connectionId: 'one',
    credentialRef: 'MCP_SIGNER', requestedScopes: ['tool.read'], stateRoot, encryptionKeyRef: 'MCP_KEY' }, resource, controller.signal, send)
  try { await use(session, requests) }
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

it('accepts an omitted scope and rejects Host-owned request headers before Token exchange', async () => {
  await withSession(() => Response.json(valid), async (session, requests) => {
    await expect(session.fetch(resource, { headers: { cookie: 'fixture' } })).rejects.toMatchObject({ code: 'MCP_MACHINE_CONFIGURATION' })
    await expect(session.fetch('https://resource.example/other')).rejects.toMatchObject({ code: 'MCP_MACHINE_CONFIGURATION' })
    expect(requests).not.toContain(`${issuer}/token`)
    expect(await (await session.fetch(resource)).json()).toEqual({ ok: true })
  })
})
