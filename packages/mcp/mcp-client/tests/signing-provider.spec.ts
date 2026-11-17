import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import LocalCredentials from '@deepseek-ai/dsh-credentials-local'
import { expect, it } from 'vitest'
import type { McpSigningTarget } from '../src/machine-types.ts'
import { credentialSigner, McpSigningProviderRegistry } from '../src/signing-provider.ts'

const config = { clientId: 'https://identity.example/client.json', keyId: 'published-key',
  issuer: 'https://issuer.example', resource: 'https://resource.example/mcp' }
const signer = credentialSigner(config)
function target(expiresAt = Date.now() + 60_000): McpSigningTarget {
  return { profile: 'mcp_machine', issuer: config.issuer, resource: config.resource, tokenEndpoint: `${config.issuer}/token`,
    sources: { resource: config.resource, authorizationServer: config.issuer }, expiresAt, metadataDigest: 'fixture' }
}

it('rejects unnamed keys, directory client identifiers and invalid registration names', async () => {
  const ctx = new Context()
  try {
    expect(() => credentialSigner({ ...config, keyId: ' ' })).toThrow('published key id')
    expect(() => credentialSigner({ ...config, clientId: 'https://identity.example/' })).toThrow('published key id')
    const registry = new McpSigningProviderRegistry(ctx)
    expect(() => registry.register('credentials', signer)).toThrow('provider name')
    expect(() => registry.register('invalid/name', signer)).toThrow('provider name')
  } finally { await ctx.fiber.dispose() }
})

it('fails closed on target, credential, key format and signing lease changes', async () => {
  const ctx = new Context()
  const dir = await mkdtemp(join(tmpdir(), 'mcp-signer-'))
  const ref = credentialRef('SIGNER_KEY')
  const bind = (bound = target()) => signer.bind(ctx, { credentialRef: ref, target: bound, requestedScopes: ['catalog.read'] })
  const pem = (namedCurve: string) => generateKeyPairSync('ec', { namedCurve }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  try {
    await expect(bind({ ...target(), issuer: 'https://other.example' })).rejects.toThrow('issuer or resource')
    await expect(bind({ ...target(), resource: 'https://resource.example/other' })).rejects.toThrow('issuer or resource')
    await expect(bind()).rejects.toMatchObject({ code: 'MCP_CREDENTIALS_UNAVAILABLE' })
    await ctx.plugin(LocalCredentials, { dshHome: dir, watch: false })
    const credentials = ctx.get('credentials')!
    await expect(bind()).rejects.toMatchObject({ code: 'MCP_CREDENTIAL_NOT_FOUND' })
    for (const value of ['wrong format', pem('secp384r1')]) {
      await credentials.set(ref, value)
      await expect(bind()).rejects.toThrow('P-256 PKCS#8 PEM')
    }
    await credentials.set(ref, pem('prime256v1'))
    const expired = await bind(target(Date.now() - 1))
    await expect(expired.assertActive()).rejects.toMatchObject({ code: 'MCP_MACHINE_SIGNER_UNAVAILABLE' })
    const disposed = await bind()
    disposed.dispose()
    await expect(disposed.signClientAssertion()).rejects.toMatchObject({ code: 'MCP_MACHINE_SIGNER_UNAVAILABLE' })
    const current = await bind()
    await credentials.set(ref, pem('prime256v1'))
    await expect(current.assertActive()).rejects.toMatchObject({ code: 'MCP_MACHINE_SIGNER_UNAVAILABLE' })
  } finally {
    await ctx.fiber.dispose()
    await rm(dir, { recursive: true, force: true })
  }
})
