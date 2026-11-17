/** Cordis-owned registrations and the built-in credentials signing provider. */
import { createHash, createPrivateKey, createPublicKey, randomUUID, sign } from 'node:crypto'
import { Context } from '@deepseek-ai/cordis'
import { McpLocalError } from './diagnostic.ts'
import { machineUrl } from './machine-http.ts'
import type { CredentialSigningConfig, McpSigningProvider } from './machine-types.ts'

const namePattern = /^[a-z][a-z0-9-]{0,63}$/u
const prefix = 'mcpSigningProvider:'
interface RegisteredProvider { readonly generation: string; readonly provider: McpSigningProvider }

/** Host-only service definition for named MCP signing providers. */
export class McpSigningProviderRegistry {
  constructor(private readonly context: Context) {}

  /**
   * Register a provider in the current Host for the owning plugin's lifetime.
   * @param name - Unique Host-wide name. `credentials` is reserved.
   * @param provider - Target-bound signer implementation.
   * @returns The registration disposer. Removing a registration invalidates its leases.
   */
  register(name: string, provider: McpSigningProvider): () => void {
    if (name === 'credentials' || !namePattern.test(name)) {
      throw new McpLocalError('Invalid MCP signing provider name', 'MCP_MACHINE_CONFIGURATION')
    }
    const key = prefix + name
    const hostKeys = this.context[Context.root][Context.isolate]
    hostKeys[key] ??= Symbol(key)
    return this.context.isolate(key, hostKeys[key]).provide(key, Object.freeze({ generation: randomUUID(), provider }))
  }
}

/** Look up a live provider in the same Host as the MCP caller.
 * @param context - MCP caller context.
 * @param name - Explicitly configured signer name.
 * @returns The current registration, if active.
 */
export function signingProvider(context: Context, name: string): RegisteredProvider | undefined {
  return context[Context.root].get(prefix + name) as RegisteredProvider | undefined
}

/** Bind an operator-pinned P-256 private key from the existing credentials service.
 * @param config - Public client id, key id and exact permitted issuer and resource.
 * @returns A signer that re-resolves and verifies the credential before signing or Token use.
 */
export function credentialSigner(config: Readonly<CredentialSigningConfig>): McpSigningProvider {
  if (machineUrl(config.clientId).pathname === '/' || !config.keyId.trim()) {
    throw new McpLocalError('Set a CIMD document URL and published key id', 'MCP_MACHINE_CONFIGURATION')
  }
  const policyVersion = createHash('sha256').update(JSON.stringify(config)).digest('base64url')
  return {
    async bind(context, input) {
      if (config.issuer !== input.target.issuer || config.resource !== input.target.resource) {
        throw new McpLocalError('MCP signer issuer or resource does not match the configured target', 'MCP_MACHINE_SIGNER_UNAVAILABLE')
      }
      const { credentialRef } = await import('@deepseek-ai/dsh-credentials')
      const ref = credentialRef(input.credentialRef)
      const read = async () => {
        const credentials = context.get('credentials')
        if (!credentials) throw new McpLocalError('Mount a Host credentials provider first', 'MCP_CREDENTIALS_UNAVAILABLE')
        const resolved = await credentials.resolve(ref)
        if (!resolved) throw new McpLocalError('MCP signing credential is unavailable', 'MCP_CREDENTIAL_NOT_FOUND')
        try {
          if (!resolved.value.startsWith('-----BEGIN PRIVATE KEY-----')) throw new Error('expected PKCS#8')
          const key = createPrivateKey(resolved.value)
          if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('expected P-256')
          const keyVersion = createHash('sha256').update(createPublicKey(key).export({ type: 'spki', format: 'der' })).digest('base64url')
          return { key, keyVersion }
        } catch (_invalidPrivateKey) {
          throw new McpLocalError('Configure an MCP signing credential containing a P-256 PKCS#8 PEM key', 'MCP_MACHINE_SIGNER_UNAVAILABLE')
        }
      }
      const { keyVersion } = await read()
      let disposed = false
      const current = async () => {
        const result = await read()
        if (disposed || Date.now() >= input.target.expiresAt || result.keyVersion !== keyVersion) {
          throw new McpLocalError('MCP signing credential or target changed', 'MCP_MACHINE_SIGNER_UNAVAILABLE')
        }
        return result.key
      }
      return {
        identity: { clientId: config.clientId, keyId: config.keyId, algorithm: 'ES256', keyVersion, policyVersion },
        async assertActive() { await current() },
        async signClientAssertion() {
          const key = await current()
          const now = Math.floor(Date.now() / 1000)
          const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: config.keyId, typ: 'client-authentication+jwt' })).toString('base64url')
          const claims = Buffer.from(JSON.stringify({ iss: config.clientId, sub: config.clientId, aud: input.target.issuer,
            iat: now, exp: now + 60, jti: randomUUID() })).toString('base64url')
          const signingInput = `${header}.${claims}`
          return `${signingInput}.${sign('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`
        },
        dispose() { disposed = true },
      }
    },
  }
}
