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
  del(id) { try { fs.unlinkSync(path.join(STATE_DIR, id + '.json')); } catch (e) {} },
  // List every session on disk. sessionId comes from the FILENAME (the record carries no sessionId
  // field). Per-file try/catch: a corrupt or half-written file is skipped this sweep, never kills the
  // whole list — so one in-flight write can't stop the autonomous ticker (audit B4/B7).
  list() {
    let names;
    try { names = fs.readdirSync(STATE_DIR).filter(n => n.endsWith('.json')); } catch (e) { return []; }
    const out = [];
    for (const n of names) {
      try { out.push(Object.assign({ sessionId: n.slice(0, -5) }, JSON.parse(fs.readFileSync(path.join(STATE_DIR, n), 'utf8')))); }
      catch (e) { /* corrupt/partial file — skip this sweep, retry next */ }
    }
    return out;
  }
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

  // Reveal core — reusable by the HTTP handler AND the autonomous ticker.
  // Idempotent: once revealed, the FULL response object is cached on the session file and re-served
  // verbatim, never recomputed (a later drand-mirror discrepancy can't change a settled result — B6).
  // Returns { status:'unknown' } | { status:'too_early', round, roundTime } | { status:'revealed', record }.
  async function performReveal(sessionId) {
    const s = pending.get(sessionId);
    if (!s) return { status: 'unknown' };
    if (s.revealed && s.result) return { status: 'revealed', record: s.result };          // cached — no recompute
    if (s.roundTime > Math.floor(Date.now() / 1000)) return { status: 'too_early', round: s.round, roundTime: s.roundTime };
    let r;
    try { r = await drand.fetchRound(s.round, { fetch: globalThis.fetch, hashBytes, base: DRAND_BASE || undefined }); }
    catch (e) { const err = new Error('drand fetch failed: ' + e.message); err.code = 'DRAND'; throw err; }
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
    // The FULL response — byte-identical to what /reveal returned before this refactor. Cache THIS
    // (assembled), not just host.draw's `dr`, so every re-serve is identical in shape (audit B6).
    const record = Object.assign({}, dr, {
      serverSeed: s.serverSeed, commitment: s.commitment,
      drand: { beacon: drand.QUICKNET.beacon, chainHash: drand.QUICKNET.chainHash, round: s.round,
               randomness: r.randomness, roundTime: s.roundTime,
               verifyUrl: 'https://api.drand.sh/' + drand.QUICKNET.chainHash + '/public/' + s.round },
      commitmentHash: s.commitmentHash,
      commitmentAnchor: { kind: 'rfc3161', commitmentHash: s.commitmentHash, genTime: commitTime, roundRule: 'roundAt(genTime)+1',
                          tsa: tokens.map(t => t.tsa).join('+'), tokens, ots: s.ots || null }
    });
    // Persist result back onto the session (replaces the old pending.del). Reveal is now idempotent:
    // ticker, operator, or client may call it any number of times and get this identical record.
    s.revealed = true; s.result = record; s.revealedAt = Math.floor(Date.now() / 1000);
    pending.put(sessionId, s);
    return { status: 'revealed', record };
  }

  app.post('/reveal', async (req, res) => {
    try {
      const outcome = await performReveal((req.body || {}).sessionId);
      if (outcome.status === 'unknown')   return res.status(404).json({ error: 'unknown session' });
      if (outcome.status === 'too_early') return res.status(425).json({ error: 'round not published yet', round: outcome.round, roundTime: outcome.roundTime });
      res.json(outcome.record);
    } catch (e) {
      if (e.code === 'DRAND') return res.status(502).json({ error: e.message });          // same 502 surface as before
      res.status(500).json({ error: e.message });
    }
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

  // Read-only status — lets anyone watch a draw get revealed WITHOUT triggering a reveal and without
  // leaking serverSeed (still secret pre-reveal). This is how you SEE the ticker work: poll after
  // closing the tab; `revealed:true` appearing on its own means the server did it, not you.
  app.get('/draw-status/:sessionId', (req, res) => {
    const s = pending.get(req.params.sessionId);
    if (!s) return res.status(404).json({ error: 'unknown session' });
    const now = Math.floor(Date.now() / 1000);
    if (s.revealed && s.result) {
      return res.json({ revealed: true, revealedAt: s.revealedAt || null, tier: s.result.tier,
                        round: s.round, drawId: s.result.drawId || s.result.gameId || null });
    }
    res.json({ revealed: false, round: s.round, roundTime: s.roundTime, now, roundPublished: s.roundTime <= now });
    // NB: never returns serverSeed/result before reveal — those stay secret until performReveal runs.
  });

  // ---- autonomous reveal ticker ------------------------------------------------------------------
  // Reveals each session within ~REVEAL_TICK_MS of its round publishing, no human in the loop
  // (closes "nobody is awake to POST /reveal"). The race ticker-vs-manual is benign: both fetch the
  // same fixed round R, host.draw is deterministic, so the cached record is identical (last write wins).
  //   B1: this runs in the Node event loop — on a host that suspends idle processes (Render free) it
  //       only fires while kept warm by inbound traffic; the /health keep-alive ping IS that warmth.
  //       If the pinger stops, autonomous reveal stops silently.
  //   B2: state lives in STATE_DIR (tmpdir by default), ephemeral on such hosts — a restart in the
  //       commit→reveal window loses serverSeed and the draw is unrecoverable. Durable autonomy needs
  //       persistent storage (Firestore) — deliberately a separate change, not this patch.
  const REVEAL_TICK_MS  = Number(process.env.UVS_REVEAL_TICK_MS  || 5000);
  const REVEAL_RETAIN_S = Number(process.env.UVS_REVEAL_RETAIN_S || 24 * 3600);   // delete revealed files after this (B3)
  let _ticking = false;                                                            // reentrancy guard (B5)
  async function revealTick() {
    if (_ticking) return;                          // previous (slow) sweep still running — skip
    _ticking = true;
    try {
      const now = Math.floor(Date.now() / 1000);
      for (const s of pending.list()) {
        try {
          if (s.revealed) {                        // retention: drop long-settled files so STATE_DIR can't grow forever (B3)
            if (s.revealedAt && now - s.revealedAt > REVEAL_RETAIN_S) pending.del(s.sessionId);
            continue;
          }
          if (s.roundTime > now) continue;         // round not published yet (same gate as the handler)
          const out = await performReveal(s.sessionId);
          if (out.status === 'revealed') console.log('[3B-auto] revealed ' + s.sessionId + ' round ' + s.round);
        } catch (e) { console.warn('[3B-auto] reveal ' + s.sessionId + ' failed: ' + e.message); }  // one bad session never stops the sweep
      }
    } finally { _ticking = false; }
  }
  const _revealTimer = setInterval(revealTick, REVEAL_TICK_MS);
  if (_revealTimer.unref) _revealTimer.unref();    // the express server keeps the process alive; the ticker must not

  // Same shape the /draw page polls (BACKEND+'/health') to enable Anchored mode.
  app.get('/health', (req, res) => res.json({
    ok: true, tsas: TSAS.map(t => t.name), roundRule: 'roundAt(genTime)+1',
    ots: ots.available(), ca: caState,
    autoReveal: { enabled: true, tickMs: REVEAL_TICK_MS,
      note: 'autonomous reveal depends on the keep-alive ping (event loop suspends when the host is idle); STATE_DIR is ephemeral (tmpdir) — durable autonomy pending Firestore' }
  }));

  return { tsas: TSAS.map(t => t.name), caFile: TSA_CA, host };
}

module.exports = { mountAnchoredDraws };
