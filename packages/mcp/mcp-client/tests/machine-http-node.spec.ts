import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
import { expect, it, vi } from 'vitest'
import { machineFetch } from '../src/machine-http.ts'

vi.mock('node:dns/promises', () => ({ lookup: async () => [{ address: '8.8.8.8', family: 4 }] }))
vi.mock('node:https', () => ({
  request: (url: URL, options: { ca?: string; rejectUnauthorized?: boolean }, callback: (response: Readable) => void) => {
    expect(url.hostname).toBe('target.example')
    expect(options.ca).toBeUndefined()
    expect(options.rejectUnauthorized).toBe(true)
    const request = new EventEmitter()
    return Object.assign(request, { end() {
      const response = Object.assign(Readable.from([Buffer.from('opaque')], { objectMode: false }),
        { headers: { 'x-incomplete-fixture-header': undefined } })
      callback(response)
      request.emit('close')
    } })
  },
}))

it('fails closed when an ordinary HTTPS callback has no status and skips absent headers', async () => {
  const response = await machineFetch('https://target.example/mcp')
  expect(response.status).toBe(500)
  expect(response.headers.has('x-incomplete-fixture-header')).toBe(false)
  expect(await response.text()).toBe('opaque')
})
