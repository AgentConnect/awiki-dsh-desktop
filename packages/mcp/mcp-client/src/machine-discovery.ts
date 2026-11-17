/** Public MCP resource and OAuth issuer discovery for CIMD machine connections. */
import { createHash } from 'node:crypto'
import { buildDiscoveryUrls, Client, extractWWWAuthenticateParams, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { McpLocalError } from './diagnostic.ts'
import { machineFetch, machineJson, machineUrl } from './machine-http.ts'
import type { McpSigningTarget } from './machine-types.ts'

async function challengeSource(endpoint: string, send: typeof machineFetch, signal: AbortSignal): Promise<string | undefined> {
  let source: string | undefined
  const transport = new StreamableHTTPClientTransport(new URL(endpoint), {
    fetch: async (input, init) => {
      const request = new Request(input, init)
      if (request.url !== new URL(endpoint).href || request.headers.has('authorization')) {
        throw new McpLocalError('CIMD discovery attempted to leave the configured MCP endpoint', 'MCP_MACHINE_DISCOVERY')
      }
      const response = await send(request, { signal: AbortSignal.any([request.signal, signal]) })
      if (response.status === 401 && /^Bearer\s/iu.test(response.headers.get('www-authenticate') ?? '')) {
        source = extractWWWAuthenticateParams(response).resourceMetadataUrl?.href
      }
      return response
    },
  })
  const client = new Client({ name: 'dsh-mcp-client', version: '0.0.1' }, { capabilities: {}, versionNegotiation: { mode: 'auto' } })
  try {
    await client.connect(transport, { signal })
  } catch (_negotiationStopped) {
    // A protected endpoint can interrupt negotiation; its challenge, if present, is the only evidence used here.
  } finally {
    try {
      if (transport.sessionId) await transport.terminateSession()
    } finally {
      await client.close()
    }
  }
  signal.throwIfAborted()
  return source
}

async function firstMetadata(candidates: readonly string[], send: typeof machineFetch, signal: AbortSignal) {
  for (const url of candidates) {
    machineUrl(url)
    const response = await send(url, { signal, headers: { accept: 'application/json' } })
    if (response.status === 404 || response.status === 410) {
      await response.body?.cancel()
      continue
    }
    if (response.status !== 200) {
      await response.body?.cancel()
      throw new McpLocalError('MCP OAuth metadata request failed', 'MCP_MACHINE_DISCOVERY')
    }
    return { url, metadata: await machineJson(response) }
  }
  throw new McpLocalError('MCP OAuth metadata is unavailable', 'MCP_MACHINE_DISCOVERY')
}

/** Discover an exact resource and a single compatible authorization server.
 * @param endpoint - Configured MCP resource URL.
 * @param selectedIssuer - Optional exact issuer pin.
 * @param send - Pinned HTTPS transport for every request.
 * @param signal - Connection cancellation signal and startup budget.
 * @returns Validated discovery evidence for a target-bound signing provider.
 */
export async function discoverMachineTarget(endpoint: string, selectedIssuer: string | undefined, send: typeof machineFetch,
  signal: AbortSignal): Promise<McpSigningTarget> {
  const resource = machineUrl(endpoint)
  const challenge = await challengeSource(endpoint, send, signal)
  const candidates = challenge ? [challenge] : [...new Set([
    `${resource.origin}/.well-known/oauth-protected-resource${resource.pathname === '/' ? '' : resource.pathname}`,
    `${resource.origin}/.well-known/oauth-protected-resource`,
  ])]
  const protectedResource = await firstMetadata(candidates, send, signal)
  const issuers = protectedResource.metadata.authorization_servers
  if (protectedResource.metadata.resource !== endpoint || !Array.isArray(issuers) || !issuers.length || issuers.length > 16
    || !issuers.every(value => typeof value === 'string')) {
    throw new McpLocalError('OAuth metadata does not identify the configured MCP resource', 'MCP_MACHINE_DISCOVERY')
  }
  const advertised = [...new Set<string>(issuers)]
  for (const issuer of advertised) machineUrl(issuer)
  const issuer = selectedIssuer ?? (advertised.length === 1 ? advertised[0] : undefined)
  if (!issuer || !advertised.includes(issuer)) {
    throw new McpLocalError('Configure an issuer that exactly matches the advertised authorization server', 'MCP_MACHINE_DISCOVERY')
  }
  const as = await firstMetadata(buildDiscoveryUrls(issuer).map(({ url }) => url.href), send, signal)
  const metadata = as.metadata
  const supported = [
    ['grant_types_supported', 'client_credentials'],
    ['token_endpoint_auth_methods_supported', 'private_key_jwt'],
    ['token_endpoint_auth_signing_alg_values_supported', 'ES256'],
  ] as const
  if (metadata.issuer !== issuer || metadata.client_id_metadata_document_supported !== true || typeof metadata.token_endpoint !== 'string'
    || supported.some(([key, value]) => !Array.isArray(metadata[key]) || !metadata[key].includes(value))) {
    throw new McpLocalError('The authorization server does not advertise the required CIMD machine profile', 'MCP_MACHINE_DISCOVERY')
  }
  machineUrl(metadata.token_endpoint)
  if (metadata.revocation_endpoint !== undefined && typeof metadata.revocation_endpoint !== 'string') {
    throw new McpLocalError('Invalid OAuth revocation endpoint', 'MCP_MACHINE_DISCOVERY')
  }
  if (metadata.revocation_endpoint !== undefined) machineUrl(metadata.revocation_endpoint)
  return Object.freeze({ profile: 'mcp_machine', issuer, resource: endpoint, tokenEndpoint: metadata.token_endpoint,
    ...(metadata.revocation_endpoint === undefined ? {} : { revocationEndpoint: metadata.revocation_endpoint }),
    metadataDigest: createHash('sha256').update(JSON.stringify({ resource: protectedResource.metadata, authorizationServer: metadata })).digest('hex'),
    expiresAt: Date.now() + 300_000,
    sources: Object.freeze({ resource: protectedResource.url, authorizationServer: as.url }) })
}
