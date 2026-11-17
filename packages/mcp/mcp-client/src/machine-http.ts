/** HTTPS transport with DNS pinning and no redirects or ambient credentials. @module */
import { proxyRouteFor } from '@deepseek-ai/dsh-http-proxy'
import { lookup } from 'node:dns/promises'
import { request } from 'node:https'
import { BlockList, isIP } from 'node:net'
import { Readable } from 'node:stream'

const denied = new BlockList()
for (const [network, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]] as const) denied.addSubnet(network, prefix)
const globalV6 = new BlockList()
globalV6.addSubnet('2000::', 3, 'ipv6')
denied.addSubnet('2001:db8::', 32, 'ipv6')
denied.addSubnet('2001::', 23, 'ipv6')
denied.addSubnet('2002::', 16, 'ipv6')
denied.addSubnet('3fff::', 20, 'ipv6')

/** Validate an exact HTTPS identity URL without rewriting its spelling.
 * @param value - Wire URL.
 * @returns Parsed URL after validation.
 */
export function machineUrl(value: string): URL {
  let url: URL
  try { url = new URL(value) } catch { throw new Error('invalid_target') }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search || value.length > 2048
    || /\s|\\|[\u0000-\u001f]/u.test(value) || url.href !== value && url.href !== value + '/') throw new Error('invalid_target')
  return url
}

/** Reject non-public DNS answers, including IPv4-mapped IPv6.
 * @param address - Resolved numeric address.
 * @returns Whether the destination is publicly routable.
 */
export function publicAddress(address: string): boolean {
  const family = isIP(address)
  return family === 4 ? !denied.check(address, 'ipv4')
    : family === 6 && globalV6.check(address, 'ipv6') && !denied.check(address, 'ipv6')
}

/** Require the supported direct route from the process-wide Host proxy authority.
 * @param value - Exact HTTPS destination.
 * @returns Nothing when the Host policy permits the pinned direct lane.
 */
export function assertMachineDirectRoute(value: string | URL): void {
  const url = value instanceof URL ? value : machineUrl(value)
  if (proxyRouteFor(url).proxied) throw new Error('proxy_egress_unsupported')
}

/** Send one request to the validated DNS address; HTTPS still verifies the original hostname.
 * @param input - Request URL or Request object.
 * @param init - Fetch-compatible request fields.
 * @param beforeSend - Final authorization gate after destination and body preparation.
 * @param deadline - Bound the complete OAuth exchange or just MCP connection setup.
 * @returns A streaming response. Caller owns body cancellation.
 */
export async function machineFetch(input: string | URL | Request, init: RequestInit = {},
  beforeSend?: () => Promise<void>, deadline: 'oauth' | 'mcp' = 'oauth'): Promise<Response> {
  return requestMachine(input, init, undefined, beforeSend, deadline)
}

/** Test-only exact-origin loopback transport with an explicit ephemeral CA.
 * @param options - Exact HTTPS loopback origin and trusted test certificate.
 * @returns The same pinned transport with a bounded isolated test exception.
 */
export function createTestMachineFetch(options: { origin: string; ca: string }): typeof machineFetch {
  const url = machineUrl(options.origin)
  if (process.env.NODE_ENV !== 'test' || url.origin !== options.origin || !['localhost', '127.0.0.1'].includes(url.hostname) || !options.ca) throw new Error('test_transport_forbidden')
  return (input, init = {}, beforeSend, deadline = 'oauth') => requestMachine(input, init, options, beforeSend, deadline)
}

async function requestMachine(input: string | URL | Request, init: RequestInit, test?: { origin: string; ca: string },
  beforeSend?: () => Promise<void>, deadline: 'oauth' | 'mcp' = 'oauth'): Promise<Response> {
  if (!(input instanceof Request)) machineUrl(String(input))
  const outgoing = new Request(input, { ...init, redirect: 'manual', credentials: 'omit' })
  const budget = new AbortController()
  const timer = setTimeout(() => budget.abort(), 30_000)
  timer.unref()
  const stopTimer = () => clearTimeout(timer)
  try {
    if (outgoing.headers.has('host')) throw new Error('managed_authentication_header')
    const url = machineUrl(outgoing.url)
    assertMachineDirectRoute(url)
    if (test && url.origin !== test.origin) throw new Error('unsafe_target')
    const signal = AbortSignal.any([outgoing.signal, budget.signal])
    if (signal.aborted) throw new Error('network_failure')
    const addresses = await withAbort(lookup(url.hostname.replace(/^\[|\]$/gu, ''), { all: true, verbatim: true }), signal)
    if (addresses.length > 32 || addresses.some(value => !publicAddress(value.address) && !(test && url.origin === test.origin && (value.address === '::1' || /^127(?:\.[0-9]{1,3}){3}$/u.test(value.address))))) throw new Error('unsafe_target')
    const selected = (test ? addresses.find(value => value.address === '127.0.0.1') : undefined) ?? addresses[0]
    if (!selected) throw new Error('unsafe_target')
    const body = await requestBody(outgoing, signal)
    await beforeSend?.()
    signal.throwIfAborted()
    return await new Promise<Response>((resolve, reject) => {
      const req = request(url, {
        method: outgoing.method, headers: Object.fromEntries(outgoing.headers), signal,
        agent: false, rejectUnauthorized: true, ...(test ? { ca: test.ca } : {}),
        lookup: (_hostname, options, callback) => {
          if (options.all) callback(null, [selected])
          else callback(null, selected.address, selected.family)
        },
        maxHeaderSize: 16384,
      }, (response) => {
        const headers = new Headers()
        for (const [name, value] of Object.entries(response.headers)) {
          if (Array.isArray(value)) for (const item of value) headers.append(name, item)
          else if (value !== undefined) headers.set(name, value)
        }
        const status = response.statusCode ?? 500
        if ([204, 205, 304].includes(status)) { response.resume(); resolve(new Response(null, { status, headers })); return }
        resolve(new Response(Readable.toWeb(response) as ReadableStream<Uint8Array>, { status, headers }))
      })
      if (deadline === 'mcp') req.once('socket', socket => socket.once('secureConnect', stopTimer))
      req.once('close', stopTimer)
      req.on('error', () => reject(new Error('network_failure')))
      req.end(body)
    })
  } catch (error) {
    stopTimer()
    try { await outgoing.body?.cancel() } catch { /* The body reader owns its read failure and may already be closed. */ }
    if (error instanceof Error && ['unsafe_target', 'invalid_target', 'request_too_large', 'managed_authentication_header', 'proxy_egress_unsupported'].includes(error.message)) throw error
    throw new Error('network_failure')
  }
}

/** Read a bounded JSON object without including response contents in errors.
 * @param response - Response to consume.
 * @returns Parsed object.
 */
export async function machineJson(response: Response): Promise<Record<string, unknown>> {
  const reader = response.body?.getReader()
  let bytes = 0
  const chunks: Uint8Array[] = []
  try {
    if ((response.headers.get('content-type') ?? '').split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
      throw new Error('incompatible_metadata')
    }
    while (reader) {
      const next = await reader.read()
      if (next.done) break
      bytes += next.value.length
      if (bytes > 65536) throw new Error('response_too_large')
      chunks.push(next.value)
    }
    const value = strictJson(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks)))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('incompatible_metadata')
    return value as Record<string, unknown>
  } catch { throw new Error('incompatible_metadata') }
  finally {
    try { await reader?.cancel() } catch { /* The read failure is already normalized; cancellation must not replace it. */ }
    reader?.releaseLock()
  }
}

/** Bound retained request bytes and cancel its producer after failure or abort. */
async function requestBody(outgoing: Request, signal: AbortSignal): Promise<Buffer | undefined> {
  const reader = outgoing.body?.getReader()
  if (!reader) return undefined
  const chunks: Uint8Array[] = []
  let bytes = 0
  try {
    while (true) {
      const next = await withAbort(reader.read(), signal)
      if (next.done) return Buffer.concat(chunks)
      bytes += next.value.length
      if (bytes > 1024 * 1024) throw new Error('request_too_large')
      chunks.push(next.value)
    }
  } finally {
    try { await reader.cancel() } catch { /* The producer may already have failed; preserve the operation failure. */ }
    reader.releaseLock()
  }
}

/** JSON.parse validates grammar; the second pass rejects duplicate names including escaped aliases. */
function strictJson(text: string): unknown {
  const value: unknown = JSON.parse(text)
  let index = 0
  const whitespace = () => { while (index < text.length && /[ \t\r\n]/u.test(text.charAt(index))) index++ }
  const string = (): string => {
    const start = index++
    while (index < text.length) {
      const char = text[index++]
      if (char === '\\') index++
      else if (char === '"') return JSON.parse(text.slice(start, index)) as string
    }
    throw new Error('incompatible_metadata')
  }
  const visit = (depth: number): void => {
    if (depth > 32) throw new Error('incompatible_metadata')
    whitespace()
    if (text[index] === '{') {
      index++; whitespace(); const names = new Set<string>()
      while (text[index] !== '}') {
        const name = string()
        if (names.has(name)) throw new Error('incompatible_metadata')
        names.add(name); whitespace(); index++; visit(depth + 1); whitespace()
        if (text[index] !== ',') break
        index++; whitespace()
      }
      index++
    } else if (text[index] === '[') {
      index++; whitespace()
      while (text[index] !== ']') {
        visit(depth + 1); whitespace()
        if (text[index] !== ',') break
        index++; whitespace()
      }
      index++
    } else if (text[index] === '"') string()
    else while (index < text.length && !/[\s,}\]]/u.test(text.charAt(index))) index++
  }
  visit(0)
  return value
}

/** Abort a DNS/body wait without leaving an abort listener behind. */
async function withAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw new Error('network_failure')
  let stop!: () => void
  const aborted = new Promise<never>((_resolve, reject) => {
    stop = () => reject(new Error('network_failure'))
    signal.addEventListener('abort', stop, { once: true })
  })
  try { return await Promise.race([operation, aborted]) }
  finally { signal.removeEventListener('abort', stop) }
}
