/** Substitute only the isolated fixture's explicitly trusted TLS route in the snapshot subprocess. */
import { registerHooks } from 'node:module'

registerHooks({
  load(url, context, nextLoad) {
    if (!url.endsWith('/packages/mcp/mcp-client/src/machine-http.ts')) return nextLoad(url, context)
    const original = JSON.stringify(`${url}?snapshot-original`)
    return { format: 'module', shortCircuit: true, source: `
      import { readFileSync } from 'node:fs';
      import { createTestMachineFetch } from ${original};
      export * from ${original};
      export const machineFetch = createTestMachineFetch({
        origin: process.env.DSH_CIMD_SNAPSHOT_ORIGIN,
        ca: readFileSync(process.env.DSH_CIMD_SNAPSHOT_TLS_CA, 'utf8'),
      });
    ` }
  },
})
