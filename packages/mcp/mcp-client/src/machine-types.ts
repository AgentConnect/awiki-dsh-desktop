/** Host-side contracts for the CIMD client-credentials flow. */
import type { Context } from '@deepseek-ai/cordis'

/** Operator-pinned settings for the built-in Cordis credentials signer. */
export interface CredentialSigningConfig {
  /** Public HTTPS client metadata document URL. */
  clientId: string
  /** Published ES256 key identifier. */
  keyId: string
  /** Exact authorization server issuer allowed by this credential. */
  issuer: string
  /** Exact MCP resource allowed by this credential. */
  resource: string
}

/** Explicit machine authentication settings for one Streamable HTTP connection. */
export interface MachineAuthentication {
  /** Use CIMD discovery and the OAuth client-credentials grant. */
  mode: 'cimd-client-credentials'
  /** Stable Host-wide connection id used for encrypted Token state. */
  connectionId: string
  /** Explicit registered signer name, or `credentials` for the built-in signer. */
  provider: string
  /** Signer-specific reference. The built-in signer resolves a Host credential reference. */
  credentialRef: string
  /** Pins an issuer if discovery advertises several. */
  issuer?: string
  /** Built-in signer settings, only for `provider: credentials`. */
  credential?: CredentialSigningConfig
  /** Minimum nonempty scope set for the connection. */
  requestedScopes: string[]
  /** Absolute protected directory for the encrypted Token and sent-Bearer history. */
  stateRoot: string
  /** Host credential reference for the 32-byte base64url storage key. */
  encryptionKeyRef: string
}

/** Target accepted by MCP discovery and supplied to the signer as evidence. */
export interface McpSigningTarget {
  readonly profile: 'mcp_machine'
  readonly issuer: string
  readonly resource: string
  readonly tokenEndpoint: string
  readonly revocationEndpoint?: string
  readonly metadataDigest: string
  readonly expiresAt: number
  readonly sources: { readonly resource: string; readonly authorizationServer: string }
}

/** Public client identity and opaque cache generations for this lease. */
export interface McpSigningIdentity {
  readonly clientId: string
  readonly keyId: string
  readonly algorithm: 'ES256'
  readonly keyVersion: string
  readonly policyVersion: string
}

/** Revocable signing permission for one caller, target and scope set. */
export interface McpSigningLease {
  readonly identity: McpSigningIdentity
  /** Recheck the current key, policy and signer availability. */
  assertActive(): Promise<void>
  /** @returns A fresh client assertion for the bound issuer. */
  signClientAssertion(): Promise<string>
  /** Release this target's signing permission. */
  dispose(): void
}

/** Host-only registration contract for a CIMD client assertion signer. */
export interface McpSigningProvider {
  /**
   * Bind the caller to the validated target and current local policy.
   * @param context - Original MCP plugin Context supplied by the Loader.
   * @param input - Credential reference, discovered target and exact requested scopes.
   * @returns The target-bound signing lease.
   */
  bind(context: Context, input: {
    readonly credentialRef: string
    readonly target: McpSigningTarget
    readonly requestedScopes: readonly string[]
  }): Promise<McpSigningLease>
}
