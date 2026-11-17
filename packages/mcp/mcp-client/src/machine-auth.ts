/** Target-bound CIMD Token exchange and authenticated SDK transport. */
import { createHash, randomUUID } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import type { Context } from '@deepseek-ai/cordis'
import { McpLocalError, McpToolError } from './diagnostic.ts'
import { discoverMachineTarget } from './machine-discovery.ts'
import { MACHINE_TOKEN_MAX_LIFETIME } from './machine-history.ts'
import { machineFetch, machineJson, machineUrl } from './machine-http.ts'
import { MachineBearerRedactor, type MachineOutputProtection } from './machine-output.ts'
import { MachineConnectionStore, type MachineToken } from './machine-store.ts'
import type { MachineAuthentication, McpSigningLease, McpSigningTarget } from './machine-types.ts'
import { credentialSigner, signingProvider } from './signing-provider.ts'

/** HTTP headers whose authority comes from the machine transport rather than profile headers. */
export const machineManagedHeaders = /^(?:host|authorization|proxy-authorization|cookie|dpop|poppy-session)$/iu

interface Binding {
  target: McpSigningTarget
  lease: McpSigningLease
  registration: string
  generation: number
  partition: string
}

/** One connection's signer lease, credential generation and SDK fetch. */
export class MachineAuthenticationSession {
  private readonly store: MachineConnectionStore
  private readonly redactor = new MachineBearerRedactor()
  private readonly scopes: readonly string[]
  private readonly builtIn?: ReturnType<typeof credentialSigner>
  private readonly signal: AbortSignal
  private readonly startedAt = Date.now()
  private lastCheck?: { wall: number; monotonic: number }
  private binding: Binding | undefined
  private target?: McpSigningTarget
  private refreshing: Promise<Binding> | undefined
  private issuing: { binding: Binding; token: Promise<MachineToken> } | undefined

  constructor(private readonly context: Context, private readonly config: Readonly<MachineAuthentication>,
    private readonly endpoint: string, signal: AbortSignal, private readonly send = machineFetch) {
    this.signal = signal
    this.scopes = Object.freeze([...new Set(config.requestedScopes)].sort())
    if (config.provider === 'credentials' && config.credential) this.builtIn = credentialSigner(config.credential)
    this.store = new MachineConnectionStore(config.stateRoot, config.connectionId, async () => {
      const { credentialRef } = await import('@deepseek-ai/dsh-credentials')
      const value = await context.get('credentials')?.resolve(credentialRef(config.encryptionKeyRef))
      if (!value || !/^[A-Za-z0-9_-]{43}$/u.test(value.value)) {
        throw new McpLocalError('Set the MCP Token storage key in the Host credentials service', 'MCP_CREDENTIAL_NOT_FOUND')
      }
      return Buffer.from(value.value, 'base64url')
    })
    this.signal.addEventListener('abort', () => { this.binding?.lease.dispose() }, { once: true })
  }

  private lookupProvider() {
    const registration = this.builtIn ? { generation: 'credentials', provider: this.builtIn }
      : signingProvider(this.context, this.config.provider)
    if (!registration) throw new McpLocalError('Mount the configured MCP signing provider', 'MCP_MACHINE_SIGNER_UNAVAILABLE')
    return registration
  }

  private async connectBinding(): Promise<Binding> {
    this.signal.throwIfAborted()
    const state = await this.store.state()
    if (state && (!state.active || state.historyUnavailable || state.migrationId !== undefined)) {
      throw new McpLocalError('MCP Token state is disabled or requires recovery', 'MCP_MACHINE_STATE_UNAVAILABLE')
    }
    const provider = this.lookupProvider()
    const issuer = this.config.credential?.issuer ?? this.config.issuer
    const target = this.target && this.target.expiresAt > Date.now() ? this.target
      : await discoverMachineTarget(this.endpoint, issuer, this.send, this.signal)
    let lease: McpSigningLease
    try {
      lease = await provider.provider.bind(this.context, { credentialRef: this.config.credentialRef, target, requestedScopes: this.scopes })
    } catch (_signerRejected) {
      throw new McpLocalError('The configured MCP signer refused the target or credential', 'MCP_MACHINE_SIGNER_UNAVAILABLE')
    }
    try {
      const { clientId, keyId, algorithm, keyVersion, policyVersion } = lease.identity
      if (machineUrl(clientId).pathname === '/' || !keyId || algorithm !== 'ES256' || !keyVersion || !policyVersion) {
        throw new McpLocalError('The signer did not provide a valid published ES256 client identity', 'MCP_MACHINE_SIGNER_UNAVAILABLE')
      }
      const partition = createHash('sha256').update(JSON.stringify([this.config.connectionId, this.config.provider, provider.generation,
        this.config.credentialRef, clientId, keyId, keyVersion, policyVersion, target.issuer, target.resource,
        target.tokenEndpoint, target.metadataDigest, this.scopes])).digest('hex')
      await this.checkLease(lease)
      const generation = await this.store.open(partition)
      await this.checkLease(lease)
      this.signal.throwIfAborted()
      if (this.lookupProvider().generation !== provider.generation) throw new McpLocalError('MCP signing provider was replaced', 'MCP_MACHINE_SIGNER_UNAVAILABLE')
      this.redactor.registerIdentity(clientId)
      this.target = target
      return this.binding = { lease, target, partition, generation, registration: provider.generation }
    } catch (error) {
      lease.dispose()
      throw error
    }
  }

  private async currentBinding(): Promise<Binding> {
    const previous = this.binding
    if (previous) {
      try { await this.assertBinding(previous); return previous }
      catch (_staleBinding) {
        if (this.binding === previous) {
          this.binding = undefined
          previous.lease.dispose()
        } else if (this.binding) return this.currentBinding()
      }
    }
    this.refreshing ??= this.connectBinding().finally(() => { this.refreshing = undefined })
    return this.refreshing
  }

  private async assertBinding(binding: Binding): Promise<void> {
    await this.checkLease(binding.lease)
    this.signal.throwIfAborted()
    if (this.binding !== binding || binding.target.expiresAt <= Date.now() || this.lookupProvider().generation !== binding.registration) {
      throw new McpLocalError('MCP authentication binding is no longer active', 'MCP_MACHINE_SIGNER_UNAVAILABLE')
    }
  }

  private async checkLease(lease: McpSigningLease): Promise<void> {
    try { await lease.assertActive() }
    catch (_signerInactive) { throw new McpLocalError('MCP signing permission is no longer active', 'MCP_MACHINE_SIGNER_UNAVAILABLE') }
  }

  private async refreshHistory(): Promise<void> {
    const expired = this.redactor.expiredReceipts()
    await this.store.pruneSentHistory(expired)
    this.redactor.acknowledgePruned(expired)
    this.redactor.observe(await this.store.sentHistory())
  }

  private async issue(binding: Binding): Promise<MachineToken> {
    const target = binding.target
    let assertion: string
    try { assertion = await binding.lease.signClientAssertion() }
    catch (_signingFailed) { throw new McpLocalError('The MCP signer could not create a client assertion', 'MCP_MACHINE_SIGNER_UNAVAILABLE') }
    this.redactor.rememberAssertion(assertion)
    const form = new URLSearchParams({ grant_type: 'client_credentials', client_id: binding.lease.identity.clientId,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
      resource: target.resource, scope: this.scopes.join(' ') })
    const acquiredAt = Date.now()
    const response = await this.send(target.tokenEndpoint, { method: 'POST', signal: this.signal,
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body: form.toString() }, async () => {
      await this.assertBinding(binding)
      await this.store.assertCurrent(binding.generation, binding.partition)
    })
    if (response.status !== 200) {
      await response.body?.cancel()
      if (response.status === 429) {
        const header = response.headers.get('retry-after')
        const suggested = header && /^[0-9]+$/u.test(header) ? Number(header) * 1000 : header ? Date.parse(header) - Date.now() : 1000
        const delay = Number.isFinite(suggested) ? Math.min(Math.max(suggested, 1000), MACHINE_TOKEN_MAX_LIFETIME) : 1000
        await this.store.defer(binding.generation, binding.partition, Date.now() + delay)
      }
      throw new McpLocalError(`MCP Token exchange returned HTTP ${response.status}`, 'MCP_MACHINE_TOKEN_FAILED')
    }
    const value = await machineJson(response)
    const lifetime = value.expires_in
    const granted = typeof value.scope === 'string' ? [...new Set(value.scope.split(' ').filter(Boolean))].sort() : this.scopes
    if (typeof value.access_token !== 'string' || !/^[\x21-\x7e]{1,32768}$/u.test(value.access_token)
      || typeof value.token_type !== 'string' || value.token_type.toLowerCase() !== 'bearer' || value.refresh_token !== undefined
      || typeof lifetime !== 'number' || !Number.isSafeInteger(lifetime) || lifetime <= 0 || lifetime * 1000 > MACHINE_TOKEN_MAX_LIFETIME
      || (value.scope !== undefined && typeof value.scope !== 'string') || JSON.stringify(granted) !== JSON.stringify(this.scopes)) {
      throw new McpLocalError('The authorization server returned an incompatible CIMD Token response', 'MCP_MACHINE_TOKEN_FAILED')
    }
    const token = { token: value.access_token, acquiredAt, expiresAt: acquiredAt + lifetime * 1000, scopes: [...granted],
      partition: binding.partition, issueId: randomUUID() }
    if (Date.now() >= token.expiresAt) throw new McpLocalError('The MCP Token expired before it could be used', 'MCP_MACHINE_TOKEN_FAILED')
    await this.store.commit(binding.generation, token, () => this.assertBinding(binding))
    return token
  }

  private async acquire(binding: Binding): Promise<MachineToken> {
    const cached = await this.store.token(binding.generation, binding.partition)
    const now = Date.now()
    const monotonic = performance.now()
    const previous = this.lastCheck
    this.lastCheck = { wall: now, monotonic }
    const rolledBack = previous !== undefined && now < previous.wall + monotonic - previous.monotonic - 1000
    if (cached && cached.acquiredAt >= this.startedAt && now >= cached.acquiredAt && cached.expiresAt > now && !rolledBack) return cached
    if (now < await this.store.retryAt(binding.generation, binding.partition)) {
      throw new McpLocalError('The MCP authorization server asked the client to wait before requesting another Token', 'MCP_MACHINE_TOKEN_FAILED')
    }
    if (this.issuing?.binding === binding) return this.issuing.token
    const flight = { binding, token: this.issue(binding).finally(() => { if (this.issuing === flight) this.issuing = undefined }) }
    this.issuing = flight
    return flight.token
  }

  /** Authenticate exactly one SDK request using the current immutable binding. */
  readonly fetch: typeof fetch = async (input, init) => {
    const original = new Request(input, init)
    const binding = await this.currentBinding()
    const signal = AbortSignal.any([this.signal, original.signal])
    const request = new Request(original, { signal })
    if (request.url !== new URL(binding.target.resource).href
      || [...request.headers.keys()].some(name => machineManagedHeaders.test(name))) {
      throw new McpLocalError('CIMD requests must use the configured MCP URL and Host-owned credentials', 'MCP_MACHINE_CONFIGURATION')
    }
    signal.throwIfAborted()
    const token = await this.acquire(binding)
    request.headers.set('authorization', `Bearer ${token.token}`)
    const check = async () => {
      signal.throwIfAborted()
      await this.assertBinding(binding)
      await this.store.assertCurrent(binding.generation, binding.partition)
      if (token.expiresAt <= Date.now()) throw new McpLocalError('MCP Token expired before dispatch', 'MCP_MACHINE_TOKEN_FAILED')
    }
    await check()
    this.redactor.remember(token.token, token.acquiredAt, token.expiresAt - token.acquiredAt)
    this.redactor.observe(await this.store.rememberSent(binding.generation, binding.partition, token, check))
    const response = await this.send(request, undefined, check)
    if (response.status === 401) {
      await response.body?.cancel()
      await this.store.invalidate(binding.generation, token)
      throw new McpToolError('MCP authentication failed after dispatch. The operation was not retried.', 'MCP_REQUEST_FAILED')
    }
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel()
      throw new McpLocalError('MCP credentials cannot follow redirects', 'MCP_MACHINE_TOKEN_FAILED')
    }
    try { await this.assertBinding(binding) }
    catch (error) { await response.body?.cancel(); throw error }
    return response
  }

  /** Protect model-visible results and validate authorization before publishing them. */
  readonly protection: MachineOutputProtection = {
    prepare: async () => { await this.currentBinding(); await this.refreshHistory() },
    begin: () => this.redactor.begin(),
    sanitize: value => this.redactor.sanitize(value),
    assertActive: async () => {
      const binding = this.binding
      if (!binding) throw new McpLocalError('MCP signing provider is unavailable', 'MCP_MACHINE_SIGNER_UNAVAILABLE')
      await this.assertBinding(binding)
      await this.refreshHistory()
      await this.store.assertCurrent(binding.generation, binding.partition)
    },
  }
}
