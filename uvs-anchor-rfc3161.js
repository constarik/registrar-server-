/* ============================================================================
 * UVS §5.4 commitment-anchor — RFC 3161 Time-Stamping (uvLottery).
 *
 * Stamps a draw's `commitmentHash` at one or more independent RFC 3161 TSAs to
 * prove the commitment existed BEFORE the future drand round R — operator-
 * independent evidence, the immediate-token path that fits a seconds-to-minutes
 * commit→R window (uvLs §5.4). Verification is the spec's reference path:
 * `openssl ts -verify`, and the token's `genTime` must be < timeOfRound(R).
 *
 * Production: POST the request to a public TSA (FreeTSA, a commercial CA).
 * Test/dev:   produce the token from a LOCAL openssl TSA (no network).
 * Uses the openssl `ts` CLI — no JS ASN.1 dependency.
 * ========================================================================== */
'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const http = require('http');

function _tmp(ext) { return path.join(os.tmpdir(), 'uvs3a_' + Math.random().toString(16).slice(2) + ext); }

// Windows OpenSSL builds often point OPENSSL_CONF at a non-existent
// "C:\Program Files\Common Files\ssl\openssl.cnf" and die on EVERY invocation.
// `openssl ts` needs no config for query/text/verify, so feed it an empty one —
// unless the caller already set a valid OPENSSL_CONF themselves.
let _emptyCnf = null;
function _opensslEnv() {
  if (process.env.OPENSSL_CONF && fs.existsSync(process.env.OPENSSL_CONF)) return process.env;
  if (!_emptyCnf) {
    try { _emptyCnf = _tmp('.cnf'); fs.writeFileSync(_emptyCnf, '# intentionally empty: openssl ts needs no config here\n'); }
    catch (e) { _emptyCnf = null; return process.env; }
  }
  return Object.assign({}, process.env, { OPENSSL_CONF: _emptyCnf });
}

/** Build a DER RFC 3161 request (.tsq) over an already-computed SHA-256 hex digest. */
function buildRequest(hashHex, openssl) {
  const out = _tmp('.tsq');
  execFileSync(openssl, ['ts', '-query', '-digest', hashHex, '-sha256', '-no_nonce', '-cert', '-out', out],
    { stdio: ['ignore', 'ignore', 'ignore'], env: _opensslEnv() });
  const buf = fs.readFileSync(out); fs.unlinkSync(out); return buf;
}

/** PRODUCTION: POST the .tsq to a public TSA (http or https); resolve the .tsr token bytes.
 *  Commercial TSAs (DigiCert, Sectigo, ...) speak plain http; FreeTSA speaks https. */
function postToTSA(tsq, tsaUrl, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(tsaUrl);
    const isHttp = u.protocol === 'http:';
    const lib = isHttp ? http : https;
    const req = lib.request({
      hostname: u.hostname, port: u.port || (isHttp ? 80 : 443), path: u.pathname + u.search, method: 'POST',
      headers: { 'Content-Type': 'application/timestamp-query', 'Content-Length': tsq.length }
    }, res => {
      if (res.statusCode && res.statusCode >= 400) { res.resume(); return reject(new Error('TSA HTTP ' + res.statusCode)); }
      const c = []; res.on('data', d => c.push(d)); res.on('end', () => resolve(Buffer.concat(c)));
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs || 15000, () => req.destroy(new Error('TSA timeout')));
    req.write(tsq); req.end();
  });
}

/** TEST/DEV: produce a token from a LOCAL openssl TSA whose config + signer live in `tsaDir`. */
function localReply(tsq, tsaDir, openssl) {
  const qf = _tmp('.tsq'), out = _tmp('.tsr');
  fs.writeFileSync(qf, tsq);
  execFileSync(openssl, ['ts', '-reply', '-config', path.join(tsaDir, 'tsa.cnf'), '-queryfile', qf, '-out', out],
    { cwd: tsaDir, stdio: ['ignore', 'ignore', 'ignore'], env: _opensslEnv() });
  const buf = fs.readFileSync(out); fs.unlinkSync(qf); fs.unlinkSync(out); return buf;
}

/** Parse the `Time stamp:` line of `openssl ts -reply -text` into unix seconds. */
function _genTime(tsr, openssl) {
  const f = _tmp('.tsr'); fs.writeFileSync(f, tsr);
  let txt = '';
  try { txt = execFileSync(openssl, ['ts', '-reply', '-in', f, '-text'], { stdio: ['ignore', 'pipe', 'ignore'], env: _opensslEnv() }).toString(); }
  finally { try { fs.unlinkSync(f); } catch (e) {} }
  const m = txt.match(/Time stamp:\s*(.+)/);
  if (!m) return null;
  const t = Date.parse(m[1].trim());
  return Number.isNaN(t) ? null : Math.floor(t / 1000);
}

/**
 * Verify a .tsr token over `hashHex` against a CA cert.
 * @returns {{ ok: boolean, genTime: number|null }}  ok = signature + digest verify; genTime in unix seconds.
 */
function verify(hashHex, tsr, caFile, openssl) {
  const f = _tmp('.tsr'); fs.writeFileSync(f, tsr);
  let ok = false;
  try {
    const r = execFileSync(openssl, ['ts', '-verify', '-digest', hashHex, '-in', f, '-CAfile', caFile],
      { stdio: ['ignore', 'pipe', 'pipe'], env: _opensslEnv() }).toString();
    ok = /Verification:\s*OK/i.test(r);
  } catch (e) { ok = /Verification:\s*OK/i.test(((e.stdout || '') + (e.stderr || '')).toString()); }
  finally { try { fs.unlinkSync(f); } catch (e) {} }
  return { ok, genTime: _genTime(tsr, openssl) };
}

/**
 * High-level: stamp `commitmentHash` at a list of TSAs and return §5.4 anchor evidence.
 * @param tsas  [{ name, url }]  (production) — or [{ name, local: tsaDir }] (test).
 * @returns {Promise<{ commitmentHash, tokens: [{ tsa, proof(base64), genTime }], errors }>}
 *
 * FAULT-TOLERANT: stamps EVERY TSA independently and keeps the ones that answer.
 * Two TSAs in different jurisdictions = the §5.4 evidence survives one TSA colluding
 * or going down (uvLs §5.4, ×2 RECOMMENDED). Requires at least one token; records the
 * rest as errors so the caller can see partial strength.
 */
async function stamp(hashHex, tsas, opts) {
  opts = opts || {};
  const openssl = opts.openssl || 'openssl';
  const tsq = buildRequest(hashHex, openssl);
  // Stamp every TSA CONCURRENTLY so total latency ≈ the slowest single TSA, not the sum —
  // this keeps every genTime tight and lets a short commit→R window stay reliable.
  const results = await Promise.all(tsas.map(async (t) => {
    try {
      const tsr = t.local ? localReply(tsq, t.local, openssl) : await postToTSA(tsq, t.url, opts.timeoutMs);
      const genTime = _genTime(tsr, openssl);
      if (genTime == null) throw new Error('token has no parseable genTime');
      return { ok: true, token: { tsa: t.name, proof: tsr.toString('base64'), genTime } };
    } catch (e) { return { ok: false, error: { tsa: t.name, error: e.message } }; }
  }));
  const tokens = results.filter(r => r.ok).map(r => r.token);
  const errors = results.filter(r => !r.ok).map(r => r.error);
  if (!tokens.length) throw new Error('all TSAs failed: ' + errors.map(e => e.tsa + ':' + e.error).join('; '));
  return { commitmentHash: hashHex, kind: 'rfc3161', tokens, errors };
}

module.exports = { buildRequest, postToTSA, localReply, verify, stamp };
