/* ============================================================================
 * 3Б — anchored uvLottery draws on the registrar host (merge of the 3A contour).
 *
 *   POST /commit        { participants, rules, model } -> sessionId, commitment, round, anchor
 *   POST /reveal        { sessionId }                  -> the 🟢 record (idempotent)
 *   GET  /draw-status/:sessionId                       -> {revealed,...} (read-only, no serverSeed pre-reveal)
 *   GET  /draws/:drawId                                -> a settled public record (durable)
 *   GET  /draws?limit=N                                -> recent settled public records
 *   POST /anchor-record { record | commitmentHash }    -> RFC-3161 notary
 *   GET  /health
 *
 * DURABILITY (audit B2): state lives in Firestore when a trailDb handle is passed in, else in
 * STATE_DIR files (ephemeral; local/no-Firebase fallback, behaviour unchanged). serverSeed is SECRET
 * until reveal: pre-reveal it sits ONLY in the private `uvs_draws_pending` collection (denied to all
 * clients by the project's default-deny rules; admin SDK bypasses). The public record (serverSeed now
 * legitimately revealed) is written to `uvs_draws` and served via the HTTP API — never client-direct.
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

// ---- file backend: file-per-session in STATE_DIR (no-Firebase / local fallback) ----
const STATE_DIR = process.env.UVS_STATE_DIR || path.join(os.tmpdir(), 'uvs3b-pending');
try { fs.mkdirSync(STATE_DIR, { recursive: true }); } catch (e) {}
const fileBackend = {
  put(id, rec) { try { fs.writeFileSync(path.join(STATE_DIR, id + '.json'), JSON.stringify(rec)); } catch (e) {} },
  get(id) { try { return JSON.parse(fs.readFileSync(path.join(STATE_DIR, id + '.json'), 'utf8')); } catch (e) { return null; } },
  del(id) { try { fs.unlinkSync(path.join(STATE_DIR, id + '.json')); } catch (e) {} },
  list() {
    let names;
    try { names = fs.readdirSync(STATE_DIR).filter(n => n.endsWith('.json')); } catch (e) { return []; }
    const out = [];
    for (const n of names) {
      try { out.push(Object.assign({ sessionId: n.slice(0, -5) }, JSON.parse(fs.readFileSync(path.join(STATE_DIR, n), 'utf8')))); }
      catch (e) { /* corrupt/partial file — skip this sweep, retry next (audit B4) */ }
    }
    return out;
  }
};

// ---- store: durable Firestore when a trailDb handle is present, else the file backend. ----
// All methods async so the caller awaits uniformly (audit B2/B3: missing an await = lost write/race).
//   Pending lives in `uvs_draws_pending` (PRIVATE — holds serverSeed until reveal).
//   Settled public record lives in `uvs_draws` (served via HTTP only; serverSeed public post-reveal).
//   markRevealed KEEPS the pending doc (revealed:true + result) so reveal stays idempotent and
//   /draw-status by sessionId keeps working; retention (ticker) deletes it after REVEAL_RETAIN_S.
const PENDING_COLL = 'uvs_draws_pending';
const PUBLIC_COLL  = 'uvs_draws';

// Lightweight list row: identity + cosmetics + counts, NOT the full record (a draw's result can be
// hundreds of KB of ranked rows). Full record stays at GET /draws/:drawId. `label` is UNTRUSTED
// display text (operator-supplied) — never an identity; real identity is the operator signature (planned).
function summarizeDraw(rec, ts) {
  return {
    drawId: rec.drawId || rec.gameId || null,
    model: rec.model || null,
    label: rec.label || null,
    tier: rec.tier || null,
    participants: Array.isArray(rec.participants) ? rec.participants.length : (Array.isArray(rec.result) ? rec.result.length : null),
    ts: ts || null,
    tsISO: ts ? new Date(ts).toISOString() : null
  };
}

function makeStore(trailDb) {
  if (!trailDb) {
    return {
      mode: 'file',
      async putPending(id, rec) { fileBackend.put(id, rec); },
      async getPending(id) { return fileBackend.get(id); },
      async delPending(id) { fileBackend.del(id); },
      async listPending() { return fileBackend.list(); },
      async markRevealed(id, rec, record) {
        rec.revealed = true; rec.result = record; rec.revealedAt = Math.floor(Date.now() / 1000);
        fileBackend.put(id, rec);
      },
      async getPublic(drawId) {
        for (const s of fileBackend.list()) if (s.revealed && s.result && (s.result.drawId === drawId || s.result.gameId === drawId)) return s.result;
        return null;
      },
      async listPublic(limit) {
        return fileBackend.list().filter(s => s.revealed && s.result)
          .sort((a, b) => (b.revealedAt || 0) - (a.revealedAt || 0)).slice(0, limit)
          .map(s => summarizeDraw(s.result, (s.revealedAt || 0) * 1000));
      }
    };
  }
  return {
    mode: 'firestore',
    async putPending(id, rec) { await trailDb.collection(PENDING_COLL).doc(id).set(rec); },
    async getPending(id) { const d = await trailDb.collection(PENDING_COLL).doc(id).get(); return d.exists ? d.data() : null; },
    async delPending(id) { try { await trailDb.collection(PENDING_COLL).doc(id).delete(); } catch (e) {} },
    async listPending() { const snap = await trailDb.collection(PENDING_COLL).get(); return snap.docs.map(d => Object.assign({ sessionId: d.id }, d.data())); },
    async markRevealed(id, rec, record) {
      rec.revealed = true; rec.result = record; rec.revealedAt = Math.floor(Date.now() / 1000);
      await trailDb.collection(PUBLIC_COLL).doc(record.drawId || record.gameId).set(Object.assign({ ts: Date.now() }, record));  // public, durable
      await trailDb.collection(PENDING_COLL).doc(id).set(rec);                                                                   // keep pending for idempotency; retention deletes later
    },
    async getPublic(drawId) { const d = await trailDb.collection(PUBLIC_COLL).doc(drawId).get(); return d.exists ? d.data() : null; },
    async listPublic(limit) { const snap = await trailDb.collection(PUBLIC_COLL).orderBy('ts', 'desc').limit(limit).get(); return snap.docs.map(d => { const r = d.data(); return summarizeDraw(r, r.ts || null); }); }
  };
}

function mountAnchoredDraws(app, opts) {
  opts = opts || {};
  const store = makeStore(opts.trailEnabled && opts.trailDb ? opts.trailDb : null);
  console.log('[3B] anchored-draw store: ' + store.mode + (store.mode === 'file' ? ' (STATE_DIR=' + STATE_DIR + ', ephemeral — durable persistence needs Firestore)' : ' (uvs_draws_pending/uvs_draws)'));
  bootstrapCA();   // async; /health reports readiness
  const host = createHost({ sha256, versions: [1, 2, 3], tsa: { caFile: TSA_CA, openssl: OPENSSL } })
    .use(makeLottery({ sha256, name: 'lottery' }));

  app.post('/commit', async (req, res) => {
    try {
      const { participants, rules, model, label } = req.body || {};
      if (!Array.isArray(participants) || !rules) return res.status(400).json({ error: 'need participants[] and rules' });
      if (new Set(participants).size !== participants.length)
        return res.status(400).json({ error: 'INVALID: duplicate participant ids — record rejected (uvLs §3.1)' });
      // optional human label for navigation — UNTRUSTED display text, NFC-normalized, capped. Not identity.
      const cleanLabel = (typeof label === 'string' && label.trim()) ? label.normalize('NFC').slice(0, 80) : null;
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
      await store.putPending(sessionId, { serverSeed, commitment, round, roundTime, genTime, participants, rules, model: model || 'tickets', label: cleanLabel, commitmentHash, anchor, ots: otsProof });
      res.json({ sessionId, commitment, round, roundTime, commitmentHash, commitmentAnchor: anchor, ots: otsProof, label: cleanLabel });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Reveal core — reusable by the HTTP handler AND the autonomous ticker.
  // Idempotent: once revealed, the FULL response object is cached on the session and re-served
  // verbatim, never recomputed (a later drand-mirror discrepancy can't change a settled result — B6).
  // Returns { status:'unknown' } | { status:'too_early', round, roundTime } | { status:'revealed', record }.
  async function performReveal(sessionId) {
    const s = await store.getPending(sessionId);
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
    // The FULL response — byte-identical to what /reveal returned before the autonomy refactor.
    const record = Object.assign({}, dr, {
      serverSeed: s.serverSeed, commitment: s.commitment,
      model: s.model || null, label: s.label || null,        // carried so /draws summaries + the record show them
      drand: { beacon: drand.QUICKNET.beacon, chainHash: drand.QUICKNET.chainHash, round: s.round,
               randomness: r.randomness, roundTime: s.roundTime,
               verifyUrl: 'https://api.drand.sh/' + drand.QUICKNET.chainHash + '/public/' + s.round },
      commitmentHash: s.commitmentHash,
      commitmentAnchor: { kind: 'rfc3161', commitmentHash: s.commitmentHash, genTime: commitTime, roundRule: 'roundAt(genTime)+1',
                          tsa: tokens.map(t => t.tsa).join('+'), tokens, ots: s.ots || null }
    });
    await store.markRevealed(sessionId, s, record);   // persist (pending: idempotency; public: durable trail)
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

  // Read-only status — watch a draw get revealed WITHOUT triggering it, and WITHOUT leaking serverSeed
  // (still secret pre-reveal). `revealed:true` appearing on its own means the server did it, not you.
  app.get('/draw-status/:sessionId', async (req, res) => {
    try {
      const s = await store.getPending(req.params.sessionId);
      if (!s) return res.status(404).json({ error: 'unknown session' });
      const now = Math.floor(Date.now() / 1000);
      if (s.revealed && s.result) {
        return res.json({ revealed: true, revealedAt: s.revealedAt || null, tier: s.result.tier,
                          round: s.round, drawId: s.result.drawId || s.result.gameId || null });
      }
      res.json({ revealed: false, round: s.round, roundTime: s.roundTime, now, roundPublished: s.roundTime <= now });
      // never returns serverSeed/result before reveal — those stay secret until performReveal runs.
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Public, durable read of SETTLED draws (served by the server via admin SDK; the collections
  // themselves stay client-closed). This is the "published without me" answer + post-restart recovery.
  app.get('/draws/:drawId', async (req, res) => {
    try { const rec = await store.getPublic(req.params.drawId); rec ? res.json(rec) : res.status(404).json({ error: 'not found' }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });
  app.get('/draws', async (req, res) => {
    try { const items = await store.listPublic(Math.min(parseInt(req.query.limit) || 20, 100)); res.json({ count: items.length, items }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  // RFC-3161 notary (+best-effort OTS) for any settled record — honest 🟡 now, OTS matures later.
  app.post('/anchor-record', async (req, res) => {
    try {
      const b = req.body || {};
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

  // ---- autonomous reveal ticker ------------------------------------------------------------------
  // Reveals each session within ~REVEAL_TICK_MS of its round publishing, no human in the loop.
  //   B1: runs in the Node event loop — on a host that suspends idle processes (Render free) it only
  //       fires while kept warm by inbound traffic; the /health keep-alive ping IS that warmth.
  //   B2: state durability now depends on the store mode — Firestore (durable) vs file (ephemeral).
  const REVEAL_TICK_MS  = Number(process.env.UVS_REVEAL_TICK_MS  || 5000);
  const REVEAL_RETAIN_S = Number(process.env.UVS_REVEAL_RETAIN_S || 24 * 3600);   // delete revealed pending after this (B3)
  let _ticking = false;                                                            // reentrancy guard (B5)
  async function revealTick() {
    if (_ticking) return;                          // previous (slow) sweep still running — skip
    _ticking = true;
    try {
      const now = Math.floor(Date.now() / 1000);
      let list = [];
      try { list = await store.listPending(); } catch (e) { console.warn('[3B-auto] listPending failed: ' + e.message); return; }
      for (const s of list) {
        try {
          if (s.revealed) {                        // retention: drop long-settled pending so it can't grow forever (B3)
            if (s.revealedAt && now - s.revealedAt > REVEAL_RETAIN_S) await store.delPending(s.sessionId);
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
    store: store.mode,
    autoReveal: { enabled: true, tickMs: REVEAL_TICK_MS,
      note: 'autonomous reveal depends on the keep-alive ping (event loop suspends when the host is idle); durability is ' + (store.mode === 'firestore' ? 'Firestore (durable)' : 'STATE_DIR files (ephemeral)') }
  }));

  return { tsas: TSAS.map(t => t.name), caFile: TSA_CA, host, store,
           _performReveal: performReveal, _revealTick: revealTick };
}

module.exports = { mountAnchoredDraws };
