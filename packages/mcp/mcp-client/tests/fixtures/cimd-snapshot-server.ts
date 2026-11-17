/** Isolated HTTPS service for the keyless CIMD recorded-session scenario. */
import { execFileSync } from 'node:child_process'
import { generateKeyPairSync, randomBytes, verify } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import type { IncomingMessage } from 'node:http'
import { createServer } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

async function textOf(request: IncomingMessage): Promise<string> {
  let text = ''
  for await (const chunk of request) text += String(chunk)
  return text
}

/** Start a dedicated TLS fixture with an ephemeral client key, Token, and certificate.
 * @returns Temporary connection inputs, observed tool calls and a disposer.
 */
export async function startCimdSnapshotServer() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-cimd-snapshot-'))
  const calls: string[] = []
  const bearer = `snapshot-cimd-${randomBytes(24).toString('base64url')}`
  let origin = ''
  let issued = 0
  let closeServer: (() => Promise<void>) | undefined
  try {
    const keyPath = join(root, 'tls-key.pem')
    const certPath = join(root, 'tls-cert.pem')
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost', '-days', '1', '-keyout', keyPath, '-out', certPath], { stdio: 'ignore' })
    const [cert, tlsKey] = await Promise.all([readFile(certPath, 'utf8'), readFile(keyPath)])
    const client = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const server = createServer({ cert, key: tlsKey }, (request, response) => {
      const json = (data: object) => response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(data))
      const handle = async () => {
        const resource = `${origin}/mcp`
        if (request.url === '/resource-metadata') return json({ resource, authorization_servers: [origin] })
        if (request.url === '/.well-known/oauth-authorization-server') return json({ issuer: origin, token_endpoint: `${origin}/token`,
          client_id_metadata_document_supported: true, grant_types_supported: ['client_credentials'],
          token_endpoint_auth_methods_supported: ['private_key_jwt'], token_endpoint_auth_signing_alg_values_supported: ['ES256'] })
        if (request.url === '/token' && request.method === 'POST') {
          const fields = new URLSearchParams(await textOf(request))
          const [header, claims, signature] = fields.get('client_assertion')?.split('.') ?? []
          const signed = header && claims && signature && verify('sha256', Buffer.from(`${header}.${claims}`),
            { key: client.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url'))
          if (!signed || fields.get('client_id') !== `${origin}/client.json` || fields.get('resource') !== resource
            || fields.get('grant_type') !== 'client_credentials' || fields.get('scope') !== 'catalog.read') return response.writeHead(400).end()
          issued++
          return json({ access_token: bearer, token_type: 'Bearer', expires_in: 600, scope: 'catalog.read' })
        }
        if (request.url !== '/mcp') return response.writeHead(404).end()
        if (!request.headers.authorization) return response.writeHead(401,
          { 'www-authenticate': `Bearer resource_metadata="${origin}/resource-metadata"` }).end()
        if (request.headers.authorization !== `Bearer ${bearer}`) return response.writeHead(401).end()
        if (request.method !== 'POST') return response.writeHead(405).end()
        const rpc = JSON.parse(await textOf(request)) as { method: string; id: number; params?: { name?: string } }
        const result = (value: object) => json({ jsonrpc: '2.0', id: rpc.id,
          result: { resultType: 'complete', ttlMs: 0, cacheScope: 'private', ...value } })
        if (rpc.method === 'server/discover') return result({ supportedVersions: ['2026-07-28'], capabilities: { tools: {} } })
        if (rpc.method === 'tools/list') return result({ tools: [{ name: 'catalog', description: 'Read one catalog entry', inputSchema: { type: 'object' } }] })
        if (rpc.method === 'tools/call' && rpc.params?.name === 'catalog') {
          calls.push('catalog')
          return result({ content: [{ type: 'text', text: `Catalog entry (probe ${bearer})` }] })
        }
        return response.writeHead(400).end()
      }
      void handle().catch(() => response.writeHead(500).end())
    })
    tlsKey.fill(0)
    closeServer = () => {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    }
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', resolve)
    })
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('CIMD snapshot did not get a fixture address')
    origin = `https://localhost:${address.port}`
    return { origin, certPath, bearer, calls, get issued() { return issued },
      signingKey: client.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), storageKey: randomBytes(32).toString('base64url'),
      async close() { await closeServer?.(); await rm(root, { recursive: true, force: true }) } }
  } catch (error) {
    await closeServer?.()
    await rm(root, { recursive: true, force: true })
    throw error
  }
}
