import { expect, it } from 'vitest'
import { discoverMachineTarget } from '../src/machine-discovery.ts'
import type { machineFetch } from '../src/machine-http.ts'

const issuer = 'https://authority.example/tenant'
const resource = 'https://resource.example/mcp'
const pathMetadata = 'https://resource.example/.well-known/oauth-protected-resource/mcp'
const rootMetadata = 'https://resource.example/.well-known/oauth-protected-resource'
const asMetadata = 'https://authority.example/.well-known/oauth-authorization-server/tenant'
const resourceDocument = { resource, authorization_servers: [issuer] }
const authorityDocument = {
  issuer, token_endpoint: 'https://authority.example/token', client_id_metadata_document_supported: true,
  grant_types_supported: ['client_credentials'], token_endpoint_auth_methods_supported: ['private_key_jwt'],
  token_endpoint_auth_signing_alg_values_supported: ['ES256'],
}

function fixture(resourceReply: () => Response, asReply: () => Response) {
  const seen: string[] = []
  const send: typeof machineFetch = async (input) => {
    const url = new Request(input).url
    seen.push(url)
    switch (url) {
      case resource: return new Response(null, { status: 401 })
      case pathMetadata: return new Response('gone', { status: 410 })
      case rootMetadata: return resourceReply()
      case asMetadata: return asReply()
      default: throw new Error('Unexpected fixture destination')
    }
  }
  return { seen, run: () => discoverMachineTarget(resource, undefined, send, new AbortController().signal) }
}

it('records well-known fallback and an advertised HTTPS revocation endpoint', async () => {
  const revocation = 'https://authority.example/revoke'
  const f = fixture(() => Response.json(resourceDocument), () => Response.json({ ...authorityDocument, revocation_endpoint: revocation }))
  expect(await f.run()).toMatchObject({ issuer, revocationEndpoint: revocation,
    sources: { resource: rootMetadata, authorizationServer: asMetadata } })
  expect(f.seen).toEqual([resource, pathMetadata, rootMetadata, asMetadata])
})

it.each([403, 404])('rejects missing or unavailable protected resource metadata (%s)', async (status) => {
  const f = fixture(() => new Response('unavailable', { status }), () => Response.json(authorityDocument))
  await expect(f.run()).rejects.toMatchObject({ code: 'MCP_MACHINE_DISCOVERY' })
  expect(f.seen).not.toContain(asMetadata)
})

it.each([
  { resource: 'https://resource.example/other', authorization_servers: [issuer] },
  { resource, authorization_servers: issuer }, { resource, authorization_servers: [] },
  { resource, authorization_servers: [123] }, { resource, authorization_servers: Array.from({ length: 17 }, () => issuer) },
  { resource, authorization_servers: [issuer, 'https://authority.example/another'] },
])('rejects protected resource metadata without one exact selected issuer %#', async (metadata) => {
  const f = fixture(() => Response.json(metadata), () => Response.json(authorityDocument))
  await expect(f.run()).rejects.toMatchObject({ code: 'MCP_MACHINE_DISCOVERY' })
  expect(f.seen).not.toContain(asMetadata)
})

it.each([
  { client_id_metadata_document_supported: false }, { token_endpoint: null }, { grant_types_supported: [] },
  { token_endpoint_auth_methods_supported: null }, { revocation_endpoint: false },
])('rejects authorization metadata incompatible with the configured grant %#', async (changed) => {
  const f = fixture(() => Response.json(resourceDocument), () => Response.json({ ...authorityDocument, ...changed }))
  await expect(f.run()).rejects.toMatchObject({ code: 'MCP_MACHINE_DISCOVERY' })
})
