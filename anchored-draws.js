/* ============================================================================
 * 3Б — anchored uvLottery draws on the registrar host (merge of the 3A contour).
 *
 * Mounts onto the registrar's existing Express app:
 *   POST /commit        { participants, rules, model }
 *        -> serverSeed + commitment; commitmentHash = SHA-256(canonical record, NO round);
 *           stamp at the RFC-3161 TSA(s); derive R = roundAt(maxGenTime)+1 (uvLs §5.4.1).
 *   POST /reveal        { sessionId }   (after round R publishes, ≤ one drand period)
 *        -> fetch randomness(R), run the draw via uvs-host (which VERIFIES the anchor
 *           against the TSA CA bundle before deriving 🟢 — audit A1), return the record.
 *   POST /anchor-record { record } | { commitmentHash }  — RFC-3161 notary for settled records.
 *   GET  /health        — same shape the /draw page polls to enable Anchored mode.
 *
 * TSA trust roots: downloaded at BOOT directly from each TSA (uvLs §5.4 — the trust
 * anchor must not come from the operator) into UVS_TSA_BUNDLE; override with UVS_TSA_CA.
 * Test mode: UVS_TSA_LOCAL=<dir with tsa.cnf> (+ its ca.pem as the CA), UVS_DRAND_BASE=<stub>.
 * ========================================================================== */
'use strict';

const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
const UVSCore = require('./uvs-core.js');
const drand = require('./uvs-anchor-drand.js');
const { makeLottery } = require('./uvs-lottery.js');
const { createHost } = require('./uvs-host.js');
const rfc = require('./uvs-anchor-rfc3161.js');
const ots = require('./uvs-anchor-ots.js');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hashBytes = (hex) => crypto.createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');

const OPENSSL = process.env.UVS_OPENSSL || 'openssl';
const DRAND_BASE = process.env.UVS_DRAND_BASE || null;   // test stub override; null = public quicknet API
const TSAS = process.env.UVS_TSA_LOCAL
  ? [{ name: 'local', local: process.env.UVS_TSA_LOCAL }]
  : [{ name: 'freetsa', url: 'https://freetsa.org/tsr' },          // ×2 independent TSAs, different
     { name: 'digicert', url: 'http://timestamp.digicert.com' }]; // operators/jurisdictions (uvLs §5.4)

// ---- TSA CA bundle: env > local-TSA ca.pem > boot-time download from the TSAs themselves ----
const TSA_ROOT_URLS = [
  'https://freetsa.org/files/cacert.pem',                          // FreeTSA root (renewed 2026-03)
  'https://cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem'     // DigiCert Trusted Root G4
];
const BUNDLE_PATH = process.env.UVS_TSA_BUNDLE || path.join(os.tmpdir(), 'uvs-tsa-ca-bundle.pem');
const TSA_CA = process.env.UVS_TSA_CA
  || (process.env.UVS_TSA_LOCAL ? path.join(process.env.UVS_TSA_LOCAL, 'ca.pem') : BUNDLE_PATH);

let caState = { ready: false, source: null, error: null };
function _get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(url + ' HTTP ' + res.statusCode)); }
      const c = []; res.on('data', d => c.push(d)); res.on('end', () => resolve(Buffer.concat(c)));
    }).on('error', reject);
  });
}
async function bootstrapCA() {
  if (process.env.UVS_TSA_CA || process.env.UVS_TSA_LOCAL) {       // explicitly provided — trust the operator's choice
    caState = { ready: fs.existsSync(TSA_CA), source: 'env', error: fs.existsSync(TSA_CA) ? null : 'UVS_TSA_CA path missing' };
    return caState;
  }
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const pems = await Promise.all(TSA_ROOT_URLS.map(_get));
      for (const p of pems) if (!/BEGIN CERTIFICATE/.test(p.toString())) throw new Error('downloaded root is not a PEM certificate');
      fs.writeFileSync(BUNDLE_PATH, Buffer.concat(pems));
      caState = { ready: true, source: 'downloaded-from-TSAs', error: null };
      console.log('[3B] TSA CA bundle ready at', BUNDLE_PATH);
      return caState;
    } catch (e) {
      caState = { ready: false, source: 'download-failed', error: e.message };
      console.warn('[3B] CA bootstrap attempt ' + attempt + ' failed:', e.message);
      await new Promise(r => setTimeout(r, attempt * 2000));
    }
  }
  console.warn('[3B] CA bundle unavailable — draws will honestly stay 🟡 (host cannot verify anchors).');
  return caState;
}

// ---- pending commit→reveal state, file-per-session (survives restarts in-window) ----
const STATE_DIR = process.env.UVS_STATE_DIR || path.join(os.tmpdir(), 'uvs3b-pending');
try { fs.mkdirSync(STATE_DIR, { recursive: true }); } catch (e) {}
const pending = {
  put(id, rec) { try { fs.writeFileSync(path.join(STATE_DIR, id + '.json'), JSON.stringify(rec)); } catch (e) {} },
  get(id) { try { return JSON.parse(fs.readFileSync(path.join(STATE_DIR, id + '.json'), 'utf8')); } catch (e) { return null; } },
  del(id) { try { fs.unlinkSync(path.join(STATE_DIR, id + '.json')); } catch (e) {} }
};

function mountAnchoredDraws(app) {
  bootstrapCA();   // async; /health reports readiness
  const host = createHost({ sha256, versions: [1, 2, 3], tsa: { caFile: TSA_CA, openssl: OPENSSL } })
    .use(makeLottery({ sha256, name: 'lottery' }));

  app.post('/commit', async (req, res) => {
    try {
      const { participants, rules, model } = req.body || {};
      if (!Array.isArray(participants) || !rules) return res.status(400).json({ error: 'need participants[] and rules' });
      if (new Set(participants).size !== participants.length)
        return res.status(400).json({ error: 'INVALID: duplicate participant ids — record rejected (uvLs §3.1)' });
      const serverSeed = crypto.randomBytes(32).toString('hex');
      const commitment = sha256(serverSeed);
      // commitmentHash does NOT include the round — the round is DERIVED from the proven timestamp,
      // so the operator has no choice over R (nothing to grind) and §5.4 holds by construction.
      const commitmentRecord = { participants, prizePool: rules.prizePool || rules, commitment, chainHash: drand.QUICKNET.chainHash };
      const commitmentHash = sha256(UVSCore.canonicalJSON(commitmentRecord));
      let anchor, otsProof;
      try {
        const [a, o] = await Promise.all([
          rfc.stamp(commitmentHash, TSAS, { openssl: OPENSSL }),
          ots.stamp(commitmentHash, { timeoutMs: 12000 }).catch(e => ({ ok: false, error: e.message }))
        ]);
        anchor = a; otsProof = (o && o.ok) ? o : null;
      } catch (e) { return res.status(502).json({ error: 'TSA stamping failed: ' + e.message }); }
      // §5.4.1: R = first drand round strictly AFTER the latest stamp (max genTime ⇒ every token predates R).
      const genTime = Math.max.apply(null, anchor.tokens.map(t => t.genTime));
      const round = drand.roundAt(genTime) + 1;
      const roundTime = drand.timeOfRound(round);
      const sessionId = crypto.randomBytes(8).toString('hex');
      pending.put(sessionId, { serverSeed, commitment, round, roundTime, genTime, participants, rules, model: model || 'tickets', commitmentHash, anchor, ots: otsProof });
      res.json({ sessionId, commitment, round, roundTime, commitmentHash, commitmentAnchor: anchor, ots: otsProof });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/reveal', async (req, res) => {
    try {
      const { sessionId } = req.body || {};
      const s = pending.get(sessionId);
      if (!s) return res.status(404).json({ error: 'unknown session' });
      if (s.roundTime > Math.floor(Date.now() / 1000)) return res.status(425).json({ error: 'round not published yet', round: s.round, roundTime: s.roundTime });
      let r;
      try { r = await drand.fetchRound(s.round, { fetch: globalThis.fetch, hashBytes, base: DRAND_BASE || undefined }); }
      catch (e) { return res.status(502).json({ error: 'drand fetch failed: ' + e.message }); }
      const tokens = s.anchor.tokens;
      const commitTime = s.genTime;
      const dr = await host.draw('lottery', {
        serverSeed: s.serverSeed, commitment: s.commitment, commitTime,
        drand: { round: s.round, randomness: r.randomness },
        commitmentAnchor: {
          kind: 'rfc3161', commitmentHash: s.commitmentHash, roundRule: 'roundAt(genTime)+1',
          proof: tokens[0].proof, genTime: commitTime, tsa: tokens.map(t => t.tsa).join('+'),
          tokens, ots: s.ots || null
        },
        participants: s.participants, rules: s.rules, model: s.model
      });
      pending.del(sessionId);
      res.json(Object.assign({}, dr, {
        serverSeed: s.serverSeed, commitment: s.commitment,
        drand: { beacon: drand.QUICKNET.beacon, chainHash: drand.QUICKNET.chainHash, round: s.round,
                 randomness: r.randomness, roundTime: s.roundTime,
                 verifyUrl: 'https://api.drand.sh/' + drand.QUICKNET.chainHash + '/public/' + s.round },
        commitmentHash: s.commitmentHash,
        commitmentAnchor: { kind: 'rfc3161', commitmentHash: s.commitmentHash, genTime: commitTime, roundRule: 'roundAt(genTime)+1',
                            tsa: tokens.map(t => t.tsa).join('+'), tokens, ots: s.ots || null }
      }));
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // RFC-3161 notary (+best-effort OTS) for any settled record — honest 🟡 now, OTS matures later.
  app.post('/anchor-record', async (req, res) => {
    try {
      const b = req.body || {};
      // Hash mode: canonical JSON when the record is integer-clean (cross-language recomputable);
      // otherwise the EXACT JSON bytes of the record (floats allowed — a settled game record like
      // PADDLA's carries physics floats, and a notary stamps bytes, not cross-language semantics).
      // The mode is returned so a verifier knows how to recompute the hash.
      let commitmentHash = b.commitmentHash || null, hashMode = b.commitmentHash ? 'provided' : null;
      if (!commitmentHash) {
        const rec = b.record || b;
        try { commitmentHash = sha256(UVSCore.canonicalJSON(rec)); hashMode = 'canonical-json'; }
        catch (e) { commitmentHash = sha256(JSON.stringify(rec)); hashMode = 'json-bytes'; }
      }
      let notary, otsProof;
      try {
        const [a, o] = await Promise.all([
          rfc.stamp(commitmentHash, TSAS, { openssl: OPENSSL }),
          ots.stamp(commitmentHash, { timeoutMs: 12000 }).catch(e => ({ ok: false, error: e.message }))
        ]);
        notary = a; otsProof = (o && o.ok) ? o : null;
      } catch (e) { return res.status(502).json({ error: 'RFC-3161 notary stamping failed: ' + e.message }); }
      res.json({
        commitmentHash, hashMode, notary, ots: otsProof, tier: 'notary',
        note: 'RFC-3161 = neutral notary (existence-at-time). A game outcome is input-seeded (no future drand round), ' +
              'so this is honest 🟡 notary now; the OpenTimestamps proof matures to 🟢 trail-immutability after a Bitcoin block confirms (~hours).'
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Same shape the /draw page polls (BACKEND+'/health') to enable Anchored mode.
  app.get('/health', (req, res) => res.json({
    ok: true, tsas: TSAS.map(t => t.name), roundRule: 'roundAt(genTime)+1',
    ots: ots.available(), ca: caState
  }));

  return { tsas: TSAS.map(t => t.name), caFile: TSA_CA, host };
}

module.exports = { mountAnchoredDraws };
