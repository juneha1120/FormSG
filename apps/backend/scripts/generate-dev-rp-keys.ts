/* eslint-disable no-console */
/**
 * Generate a fresh EC P-256 RP keyset (signing + encryption) for the MyInfo v5
 * flow against mockpass, writing the public and private JWKS to disk at the
 * paths supplied by `MYINFO_V5_RP_JWKS_PUBLIC_PATH` and
 * `MYINFO_V5_RP_JWKS_SECRET_PATH`.
 *
 * Why: we used to ship a static `__fixtures__/keys/dev-rp-*.json` pair so the
 * docker-compose dev backend had something to load. Committing private key
 * material — even a labelled dev keypair — is a foot-gun, so we generate
 * fresh keys on first container start and gitignore the output path instead.
 *
 * Idempotent: if both files already exist, exits without touching them. That
 * way restarting the backend container preserves any in-flight Singpass
 * session whose tokens were minted against the existing public JWKS. Wipe
 * `.dev-keys/` to force a rotation.
 *
 * Manual invocation:
 *   MYINFO_V5_RP_JWKS_PUBLIC_PATH=.dev-keys/rp-v5-public.json \
 *   MYINFO_V5_RP_JWKS_SECRET_PATH=.dev-keys/rp-v5-secret.json \
 *   pnpm --filter formsg-backend tsx scripts/generate-dev-rp-keys.ts
 */

import fs from 'fs'
import * as jose from 'jose'
import path from 'path'

async function main(): Promise<void> {
  const publicPath = process.env.MYINFO_V5_RP_JWKS_PUBLIC_PATH
  const secretPath = process.env.MYINFO_V5_RP_JWKS_SECRET_PATH

  if (!publicPath || !secretPath) {
    console.error(
      '[gen-dev-rp-keys] MYINFO_V5_RP_JWKS_PUBLIC_PATH and MYINFO_V5_RP_JWKS_SECRET_PATH must both be set',
    )
    process.exit(1)
  }

  if (fs.existsSync(publicPath) && fs.existsSync(secretPath)) {
    console.log(
      `[gen-dev-rp-keys] keys already present at ${publicPath} & ${secretPath} — skipping`,
    )
    return
  }

  const sig = await jose.generateKeyPair('ES256', { extractable: true })
  const enc = await jose.generateKeyPair('ECDH-ES+A256KW', {
    crv: 'P-256',
    extractable: true,
  })
  const sigPriv = await jose.exportJWK(sig.privateKey)
  const sigPub = await jose.exportJWK(sig.publicKey)
  const encPriv = await jose.exportJWK(enc.privateKey)
  const encPub = await jose.exportJWK(enc.publicKey)
  for (const k of [sigPriv, sigPub]) {
    k.use = 'sig'
    k.alg = 'ES256'
    k.kid = 'formsg-v5-sig-1'
  }
  for (const k of [encPriv, encPub]) {
    k.use = 'enc'
    k.alg = 'ECDH-ES+A256KW'
    k.kid = 'formsg-v5-enc-1'
  }

  fs.mkdirSync(path.dirname(publicPath), { recursive: true })
  fs.mkdirSync(path.dirname(secretPath), { recursive: true })
  fs.writeFileSync(
    publicPath,
    JSON.stringify({ keys: [sigPub, encPub] }, null, 2),
  )
  fs.writeFileSync(
    secretPath,
    JSON.stringify({ keys: [sigPriv, encPriv] }, null, 2),
  )
  console.log(`[gen-dev-rp-keys] wrote ${publicPath} and ${secretPath}`)
}

main().catch((e) => {
  console.error('[gen-dev-rp-keys] FAILED:', e)
  process.exit(1)
})
