import { expect, it, vi } from 'vitest'
import { discoverMachineTarget } from '../src/machine-discovery.ts'
import type { machineFetch } from '../src/machine-http.ts'

const inputs = vi.hoisted(() => ({ url: '', headers: {} as Record<string, string> }))
vi.mock('@modelcontextprotocol/client', async original => ({
  ...await original<typeof import('@modelcontextprotocol/client')>(),
  StreamableHTTPClientTransport: class DiscoveryTransport {
    sessionId = undefined
    constructor(_url: URL, protected readonly options: { fetch: typeof fetch }) {}
    probe() { return this.options.fetch(inputs.url, { headers: inputs.headers }) }
  },
  Client: class DiscoveryClient {
    async connect(transport: { probe(): Promise<Response> }) { await transport.probe() }
    async close() {}
  },
}))

it.each([
  { url: 'https://resource.example/other', headers: {} },
  { url: 'https://resource.example/mcp', headers: { authorization: 'Bearer unauthenticated-probe-fixture' } },
])('keeps discovery unauthenticated and bound to the configured address %#', async ({ url, headers }) => {
  inputs.url = url
  inputs.headers = headers
  const calls: string[] = []
  const send: typeof machineFetch = async (input) => {
    const request = new Request(input)
    calls.push(request.url)
    expect(request.headers.has('authorization')).toBe(false)
    return new Response(null, { status: 404 })
  }
  await expect(discoverMachineTarget('https://resource.example/mcp', undefined, send, new AbortController().signal))
    .rejects.toThrow('MCP OAuth metadata is unavailable')
  expect(calls).toEqual([
    'https://resource.example/.well-known/oauth-protected-resource/mcp', 'https://resource.example/.well-known/oauth-protected-resource',
  ])
})
