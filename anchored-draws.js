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
const MIN_DELAY_S = Number(process.env.UVS_MIN_DELAY_S || 60);          // floor for scheduled reveal (env-overridable for tests)
const MAX_DELAY_S = Number(process.env.UVS_MAX_DELAY_S || 7 * 24 * 3600); // ceiling: bound how long serverSeed waits in storage
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
    try { names = fs.readdirSync(STATE_DIR).filter(n => n.endsWith('.json') && !n.startsWith('rules-') && !n.startsWith('gacha-')); } catch (e) { return []; }
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

// Public summary of an OPENED draw (uvLs §5.6 anti-draw-shopping). Carries only operator-chosen,
// non-personal fields (no participants — they don't exist at /open) and the closed/abandoned status.
function summarizeRules(r) {
  return {
    drawId: r.drawId || null,
    label: r.label || null,
    prizePool: r.prizePool || null,
    rulesHash: r.rulesHash || null,
    closeBy: r.closeBy || null,
    closeByISO: r.closeBy ? new Date(r.closeBy * 1000).toISOString() : null,
    openEnded: r.openEnded || false,
    closeCondition: r.closeCondition || null,
    openedAt: r.openedAt || null,
    openedISO: r.openedAt ? new Date(r.openedAt * 1000).toISOString() : null,
    closedAt: r.closedAt || null,
    closedISO: r.closedAt ? new Date(r.closedAt * 1000).toISOString() : null,
    cancelledAt: r.cancelledAt || null,
    cancelReason: r.cancelReason || null,
    status: r.cancelledAt ? 'cancelled' : (r.closedAt ? 'closed' : 'open')
  };
}

function makeStore(trailDb) {
  if (!trailDb) {
    return {
      mode: 'file',
      async putRules(drawId, rec) { try { fs.writeFileSync(path.join(STATE_DIR, 'rules-' + drawId + '.json'), JSON.stringify(rec)); } catch (e) {} },
      async getRules(drawId) { try { return JSON.parse(fs.readFileSync(path.join(STATE_DIR, 'rules-' + drawId + '.json'), 'utf8')); } catch (e) { return null; } },
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
      },
      async listRules(limit) {
        const out = [];
        try {
          for (const f of fs.readdirSync(STATE_DIR)) {
            if (!/^rules-.*\.json$/.test(f)) continue;
            try { out.push(JSON.parse(fs.readFileSync(path.join(STATE_DIR, f), 'utf8'))); } catch (e) {}
          }
        } catch (e) {}
        return out.sort((a, b) => (b.openedAt || 0) - (a.openedAt || 0)).slice(0, limit).map(summarizeRules);
      },
      async putGacha(id, rec) { try { fs.writeFileSync(path.join(STATE_DIR, 'gacha-' + id + '.json'), JSON.stringify(rec)); } catch (e) {} },
      async getGacha(id) { try { return JSON.parse(fs.readFileSync(path.join(STATE_DIR, 'gacha-' + id + '.json'), 'utf8')); } catch (e) { return null; } }
    };
  }
  return {
    mode: 'firestore',
    async putRules(drawId, rec) { await trailDb.collection('uvs_draw_rules').doc(drawId).set(rec); },
    async getRules(drawId) { const d = await trailDb.collection('uvs_draw_rules').doc(drawId).get(); return d.exists ? d.data() : null; },
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
    async listPublic(limit) { const snap = await trailDb.collection(PUBLIC_COLL).orderBy('ts', 'desc').limit(limit).get(); return snap.docs.map(d => { const r = d.data(); return summarizeDraw(r, r.ts || null); }); },
    async listRules(limit) { const snap = await trailDb.collection('uvs_draw_rules').orderBy('openedAt', 'desc').limit(limit).get(); return snap.docs.map(d => summarizeRules(d.data())); },
    async putGacha(id, rec) { await trailDb.collection('uvs_gacha').doc(id).set(rec); },
    async getGacha(id) { const d = await trailDb.collection('uvs_gacha').doc(id).get(); return d.exists ? d.data() : null; }
  };
}

const gachaResolver = require('./gacha-resolve');
function mountAnchoredDraws(app, opts) {
  opts = opts || {};
  const store = makeStore(opts.trailEnabled && opts.trailDb ? opts.trailDb : null);
  console.log('[3B] anchored-draw store: ' + store.mode + (store.mode === 'file' ? ' (STATE_DIR=' + STATE_DIR + ', ephemeral — durable persistence needs Firestore)' : ' (uvs_draws_pending/uvs_draws)'));
  bootstrapCA();   // async; /health reports readiness
  const host = createHost({ sha256, versions: [1, 2, 3], tsa: { caFile: TSA_CA, openssl: OPENSSL } })
    .use(makeLottery({ sha256, name: 'lottery' }));

  app.post('/commit', async (req, res) => {
    try {
      const { participants, rules, model, label, delaySeconds } = req.body || {};
      if (!Array.isArray(participants) || !rules) return res.status(400).json({ error: 'need participants[] and rules' });
      if (new Set(participants).size !== participants.length)
        return res.status(400).json({ error: 'INVALID: duplicate participant ids — record rejected (uvLs §3.1)' });
      // optional human label for navigation — UNTRUSTED display text, NFC-normalized, capped. Not identity.
      const cleanLabel = (typeof label === 'string' && label.trim()) ? label.normalize('NFC').slice(0, 80) : null;
      // optional scheduled reveal. 0 = derived-R (next round, ~3s — tightest, no operator choice over R).
      // >0 = explicit-R: target round ~delay seconds ahead, picked from wall-clock and baked INTO the hash.
      // Either way the round is in the FUTURE at commit → un-grindable; delay just sets how far ahead.
      // Floor (default 60s) keeps genTime < timeOfRound(R) safe against stamp latency; ceiling bounds how
      // long serverSeed sits in durable storage before reveal.
      let delay = Number(delaySeconds) || 0;
      if (delay > 0) delay = Math.max(MIN_DELAY_S, Math.min(delay, MAX_DELAY_S));
      const serverSeed = crypto.randomBytes(32).toString('hex');
      const commitment = sha256(serverSeed);
      const prizePool = rules.prizePool || rules;
      const chainHash = drand.QUICKNET.chainHash;
      let round, roundRule, commitmentRecord;
      if (delay > 0) {
        // explicit-R: round chosen from now+delay BEFORE stamping, and included in the commitment hash.
        round = drand.roundAt(Math.floor(Date.now() / 1000) + delay) + 1;
        roundRule = 'explicit-R';
        commitmentRecord = { participants, prizePool, commitment, chainHash, round };
      } else {
        // derived-R (uvLs §5.4.1): round derived from the proven stamp; NOT in the hash; no operator choice.
        roundRule = 'roundAt(genTime)+1';
        commitmentRecord = { participants, prizePool, commitment, chainHash };
      }
      const commitmentHash = sha256(UVSCore.canonicalJSON(commitmentRecord));
      let anchor, otsProof;
      try {
        const [a, o] = await Promise.all([
          rfc.stamp(commitmentHash, TSAS, { openssl: OPENSSL }),
          ots.stamp(commitmentHash, { timeoutMs: 12000 }).catch(e => ({ ok: false, error: e.message }))
        ]);
        anchor = a; otsProof = (o && o.ok) ? o : null;
      } catch (e) { return res.status(502).json({ error: 'TSA stamping failed: ' + e.message }); }
      const genTime = Math.max.apply(null, anchor.tokens.map(t => t.genTime));   // latest stamp ⇒ every token predates R
      if (delay === 0) round = drand.roundAt(genTime) + 1;                        // derived: round known only now
      const roundTime = drand.timeOfRound(round);
      // §5.4 invariant: the stamp MUST predate the round, or the anchor proves nothing.
      if (genTime >= roundTime) return res.status(500).json({ error: 'stamp landed at/after target round (clock skew or stamp latency) — retry' + (delay ? ' with a larger delaySeconds' : '') });
      const sessionId = crypto.randomBytes(8).toString('hex');
      await store.putPending(sessionId, { serverSeed, commitment, round, roundTime, genTime, roundRule, participants, rules, model: model || 'tickets', label: cleanLabel, commitmentHash, anchor, ots: otsProof });
      res.json({ sessionId, commitment, round, roundTime, roundRule, delaySeconds: delay, commitmentHash, commitmentAnchor: anchor, ots: otsProof, label: cleanLabel });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── §5.5 two-phase: /open (Phase 0 — attest the rules BEFORE sales, no participants yet) ──
  // Fixes { drawId, prizePool } and timestamps the rulesHash at ×2 RFC-3161 TSAs, so the prize
  // list is provably frozen before tickets are sold. Print drawId on every ticket; /close later
  // with the final participants. (Closed-list operators just call /open then /close immediately.)
  app.post('/open', async (req, res) => {
    try {
      const { prizePool, rules, label, closeBy, openEnded, closeCondition } = req.body || {};
      const pool = prizePool || (rules && rules.prizePool) || rules;
      if (!pool) return res.status(400).json({ error: 'need prizePool' });
      const cleanLabel = (typeof label === 'string' && label.trim()) ? label.normalize('NFC').slice(0, 80) : null;
      // The operator MUST make the closing terms an explicit, stamped promise (uvLs §5.6): either a closeBy
      // DEADLINE, or an explicit OPEN-ENDED flag (optionally with a human close condition, e.g. "when 1000
      // tickets are sold"). Forbidding silence is the point — no quiet abandonment. Whichever is given is
      // hashed into the rules, so it's timestamped and printed on the ticket.
      let closeByTs = null, isOpenEnded = false, cond = null;
      const wantsOpenEnded = (openEnded === true || openEnded === 'true');
      if (closeBy != null && closeBy !== '') {
        if (wantsOpenEnded) return res.status(400).json({ error: 'declare EITHER a closeBy deadline OR open-ended, not both' });
        closeByTs = typeof closeBy === 'number' ? Math.floor(closeBy) : Math.floor(Date.parse(closeBy) / 1000);
        if (!Number.isFinite(closeByTs) || closeByTs <= Math.floor(Date.now() / 1000)) return res.status(400).json({ error: 'closeBy must be a future time (unix seconds or ISO 8601)' });
      } else if (wantsOpenEnded) {
        isOpenEnded = true;
        cond = (typeof closeCondition === 'string' && closeCondition.trim()) ? closeCondition.normalize('NFC').slice(0, 140) : null;
      } else {
        return res.status(400).json({ error: 'declare the closing terms: a closeBy deadline, or openEnded:true (optionally with a closeCondition)' });
      }
      const drawId = crypto.randomBytes(8).toString('hex');
      const ruleObj = { drawId, prizePool: pool };
      if (closeByTs) ruleObj.closeBy = closeByTs;
      if (isOpenEnded) { ruleObj.openEnded = true; if (cond) ruleObj.closeCondition = cond; }
      const rulesHash = sha256(UVSCore.canonicalJSON(ruleObj));
      let anchor, otsProof;
      try {
        const [a, o] = await Promise.all([
          rfc.stamp(rulesHash, TSAS, { openssl: OPENSSL }),
          ots.stamp(rulesHash, { timeoutMs: 12000 }).catch(e => ({ ok: false, error: e.message }))
        ]);
        anchor = a; otsProof = (o && o.ok) ? o : null;
      } catch (e) { return res.status(502).json({ error: 'TSA stamping failed: ' + e.message }); }
      const genTime = Math.max.apply(null, anchor.tokens.map(t => t.genTime));
      const openedAt = Math.floor(Date.now() / 1000);
      await store.putRules(drawId, { drawId, prizePool: pool, closeBy: closeByTs, openEnded: isOpenEnded, closeCondition: cond, label: cleanLabel, rulesHash, rulesAnchor: anchor, ots: otsProof, genTime, openedAt });
      res.json({ drawId, rulesHash, label: cleanLabel, closeBy: closeByTs, closeByISO: closeByTs ? new Date(closeByTs * 1000).toISOString() : null, openEnded: isOpenEnded, closeCondition: cond, openedAt, genTime, rulesAnchor: anchor, ots: otsProof,
        note: '§5.5 Phase 0 — prize rules attested (×2 RFC-3161) before sales. Print drawId on every ticket; call /close with the final participants when sales end.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── §5.5 two-phase: /close (Phase 1 — commit the final participants, reuse the attested rules) ──
  // The prizePool is loaded from the /open record (the operator cannot swap it here); the draw binds
  // to a future drand round and reveals autonomously, exactly like /commit. The public record is keyed
  // by the phase-0 drawId and carries the rules attestation as §5.5 evidence.
  app.post('/close', async (req, res) => {
    try {
      const { drawId, participants, delaySeconds, declaredCount } = req.body || {};
      if (!drawId) return res.status(400).json({ error: 'need drawId (from /open)' });
      if (!Array.isArray(participants)) return res.status(400).json({ error: 'need participants[]' });
      if (new Set(participants).size !== participants.length)
        return res.status(400).json({ error: 'INVALID: duplicate participant ids — record rejected (uvLs §3.1)' });
      const rulesRec = await store.getRules(drawId);
      if (!rulesRec) return res.status(404).json({ error: 'unknown drawId — call /open first' });
      // anti-reroll / idempotency (uvLs §5.6): one draw per drawId. A second /close is refused so an
      // operator can't quietly re-close the same opened draw and keep a spare. Open a new draw to re-run.
      if (rulesRec.closedAt) return res.status(409).json({ error: 'this drawId is already closed (one draw per drawId — re-roll prevented); open a new draw to run again', closedAt: rulesRec.closedAt, sessionId: rulesRec.sessionId || null });
      if (rulesRec.cancelledAt) return res.status(409).json({ error: 'this draw was cancelled — open a new draw to run again', cancelledAt: rulesRec.cancelledAt });
      const prizePool = rulesRec.prizePool;
      // optional blind cross-check (uvLs §5.6): if the operator declares a sold count, it MUST equal the
      // committed list — enforced HERE on the server, not just on the page (a direct POST can't bypass it).
      let decl = null;
      if (declaredCount != null && declaredCount !== '') {
        decl = parseInt(declaredCount);
        if (!Number.isInteger(decl) || decl < 0) return res.status(400).json({ error: 'declaredCount must be a non-negative integer' });
        if (decl !== participants.length) return res.status(400).json({ error: 'declaredCount does not match the committed participant list size' });
      }
      let delay = Number(delaySeconds) || 0;
      if (delay > 0) delay = Math.max(MIN_DELAY_S, Math.min(delay, MAX_DELAY_S));
      const serverSeed = crypto.randomBytes(32).toString('hex');
      const commitment = sha256(serverSeed);
      const chainHash = drand.QUICKNET.chainHash;
      let round, roundRule, commitmentRecord;
      if (delay > 0) {
        round = drand.roundAt(Math.floor(Date.now() / 1000) + delay) + 1;
        roundRule = 'explicit-R';
        commitmentRecord = { participants, prizePool, commitment, chainHash, round };
      } else {
        roundRule = 'roundAt(genTime)+1';
        commitmentRecord = { participants, prizePool, commitment, chainHash };
      }
      const commitmentHash = sha256(UVSCore.canonicalJSON(commitmentRecord));
      let anchor, otsProof;
      try {
        const [a, o] = await Promise.all([
          rfc.stamp(commitmentHash, TSAS, { openssl: OPENSSL }),
          ots.stamp(commitmentHash, { timeoutMs: 12000 }).catch(e => ({ ok: false, error: e.message }))
        ]);
        anchor = a; otsProof = (o && o.ok) ? o : null;
      } catch (e) { return res.status(502).json({ error: 'TSA stamping failed: ' + e.message }); }
      const genTime = Math.max.apply(null, anchor.tokens.map(t => t.genTime));
      if (delay === 0) round = drand.roundAt(genTime) + 1;
      const roundTime = drand.timeOfRound(round);
      if (genTime >= roundTime) return res.status(500).json({ error: 'stamp landed at/after target round — retry' + (delay ? ' with a larger delaySeconds' : '') });
      const sessionId = crypto.randomBytes(8).toString('hex');
      const rulesAttestation = { drawId, rulesHash: rulesRec.rulesHash, openedAt: rulesRec.openedAt, anchor: rulesRec.rulesAnchor, ots: rulesRec.ots || null };
      await store.putPending(sessionId, { serverSeed, commitment, round, roundTime, genTime, roundRule, participants,
        rules: { prizePool }, model: 'tickets', label: rulesRec.label, drawId, declaredCount: decl, rulesAttestation, commitmentHash, anchor, ots: otsProof });
      try { rulesRec.closedAt = Math.floor(Date.now() / 1000); rulesRec.sessionId = sessionId; await store.putRules(drawId, rulesRec); } catch (e) {}   // mark closed in the open-log (anti-reroll + anti-shopping)
      res.json({ sessionId, drawId, commitment, round, roundTime, roundRule, delaySeconds: delay, commitmentHash,
        commitmentAnchor: anchor, ots: otsProof, label: rulesRec.label, declaredCount: decl, rulesAttestation });
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
        kind: 'rfc3161', commitmentHash: s.commitmentHash, roundRule: s.roundRule || 'roundAt(genTime)+1',
        proof: tokens[0].proof, genTime: commitTime, tsa: tokens.map(t => t.tsa).join('+'),
        tokens, ots: s.ots || null
      },
      participants: s.participants, rules: s.rules, model: s.model
    });
    // The FULL response — byte-identical to what /reveal returned before the autonomy refactor.
    const record = Object.assign({}, dr, {
      serverSeed: s.serverSeed, commitment: s.commitment,
      participants: s.participants, rules: s.rules,           // self-contained: anyone recomputes from the published record (incl. §6.1 prizePool rule)
      model: s.model || null, label: s.label || null,        // carried so /draws summaries + the record show them
      drand: { beacon: drand.QUICKNET.beacon, chainHash: drand.QUICKNET.chainHash, round: s.round,
               randomness: r.randomness, roundTime: s.roundTime,
               verifyUrl: 'https://api.drand.sh/' + drand.QUICKNET.chainHash + '/public/' + s.round },
      commitmentHash: s.commitmentHash,
      commitmentAnchor: { kind: 'rfc3161', commitmentHash: s.commitmentHash, genTime: commitTime, roundRule: s.roundRule || 'roundAt(genTime)+1',
                          tsa: tokens.map(t => t.tsa).join('+'), tokens, ots: s.ots || null }
    });
    if (s.drawId) {                                   // §5.5 two-phase: key the public record by the phase-0 drawId + carry the rules attestation
      record.drawId = s.drawId;
      record.rulesAttestation = s.rulesAttestation || null;
      if (s.declaredCount != null) record.declaredCount = s.declaredCount;   // §5.6: the operator's own declared sold-count, pinned in the public record
    }
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

  // Public ledger of OPENED draws (uvLs §5.6 anti-draw-shopping). Every /open is visible here the
  // moment it happens; an entry with status:'open' that never becomes 'closed' is a draw that was
  // started and abandoned. Selective publication (open many, reveal one) becomes a visible anomaly.
  app.get('/opens', async (req, res) => {
    try {
      const items = await store.listRules(Math.min(parseInt(req.query.limit) || 50, 200));
      res.json({ count: items.length, open: items.filter(i => i.status === 'open').length, closed: items.filter(i => i.status === 'closed').length, items,
        note: 'Opened draws. status:open with no later close = started-and-abandoned. Compare against /draws (revealed) to spot draws opened but never published.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Explicit, public cancellation (uvLs §5.6). Lets an operator mark an OPEN draw as 'cancelled' so an
  // honest cancellation is distinguishable from silent abandonment. A completed (closed) draw can't be
  // cancelled. Idempotent. The real anomaly becomes: open, past its closeBy deadline, and NOT cancelled.
  app.post('/cancel', async (req, res) => {
    try {
      const { drawId, reason } = req.body || {};
      if (!drawId) return res.status(400).json({ error: 'need drawId' });
      const rulesRec = await store.getRules(drawId);
      if (!rulesRec) return res.status(404).json({ error: 'unknown drawId — call /open first' });
      if (rulesRec.closedAt) return res.status(409).json({ error: 'already closed — a completed draw cannot be cancelled', closedAt: rulesRec.closedAt });
      if (rulesRec.cancelledAt) return res.json({ drawId, status: 'cancelled', cancelledAt: rulesRec.cancelledAt, cancelReason: rulesRec.cancelReason || null });
      rulesRec.cancelledAt = Math.floor(Date.now() / 1000);
      rulesRec.cancelReason = (typeof reason === 'string' && reason.trim()) ? reason.normalize('NFC').slice(0, 140) : null;
      await store.putRules(drawId, rulesRec);
      res.json({ drawId, status: 'cancelled', cancelledAt: rulesRec.cancelledAt, cancelReason: rulesRec.cancelReason });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── uvGacha — neutral commit-reveal (honest 🟡). The host commits serverSeed BEFORE it sees the
  // player's clientSeed, so the operator can't grind a favourable pull sequence; the resolved pulls are
  // replayable byte-for-byte by the reference resolver (uvGacha §2-§4). Instant pulls are 🟡 by construction
  // (§6) — no future beacon per pull; the revealed record is notarized at ×2 RFC-3161 for existence-at-time.
  app.post('/gacha/commit', async (req, res) => {
    try {
      const { rules, rateDenominator, pullCount } = req.body || {};
      const D = rateDenominator;
      if (!rules || !Array.isArray(rules.tiers)) return res.status(400).json({ error: 'need rules.tiers[]' });
      try { gachaResolver.validateRules(rules, D); } catch (e) { return res.status(400).json({ error: e.message }); }
      const n = parseInt(pullCount);
      if (!Number.isInteger(n) || n < 1 || n > 1000) return res.status(400).json({ error: 'pullCount must be an integer 1..1000' });
      const serverSeed = crypto.randomBytes(32).toString('hex');
      const commitment = sha256(serverSeed);
      const sessionId = crypto.randomBytes(8).toString('hex');
      await store.putGacha(sessionId, { serverSeed, commitment, rateDenominator: D, rules, pullCount: n, committedAt: Math.floor(Date.now() / 1000), revealed: false });
      res.json({ sessionId, commitment, rateDenominator: D, rules, pullCount: n,
        note: 'uvGacha commit-reveal: serverSeed committed (kept private). POST clientSeed to /gacha/reveal to resolve + reveal.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/gacha/reveal', async (req, res) => {
    try {
      const { sessionId, clientSeed } = req.body || {};
      if (!sessionId) return res.status(400).json({ error: 'need sessionId (from /gacha/commit)' });
      const s = await store.getGacha(sessionId);
      if (!s) return res.status(404).json({ error: 'unknown sessionId — call /gacha/commit first' });
      if (s.revealed && s.record) return res.json(s.record);                                  // idempotent
      if (s.batch) {                                                                          // 🟢 batch: bound to a FUTURE drand round at commit (uvGacha §6)
        const now = Math.floor(Date.now() / 1000);
        if (s.roundTime > now) return res.status(425).json({ error: 'round not published yet', round: s.round, roundTime: s.roundTime });
        let dr;
        try { dr = await drand.fetchRound(s.round, { fetch: globalThis.fetch, hashBytes, base: DRAND_BASE || undefined }); }
        catch (e) { return res.status(502).json({ error: 'drand fetch failed: ' + e.message }); }
        const grec = { branch: 'uvGacha', commitment: s.commitment, serverSeed: s.serverSeed, clientSeed: s.clientSeed,
          drand: { beacon: drand.QUICKNET.beacon, chainHash: drand.QUICKNET.chainHash, round: s.round, randomness: dr.randomness, roundTime: s.roundTime,
                   verifyUrl: 'https://api.drand.sh/' + drand.QUICKNET.chainHash + '/public/' + s.round },
          rateDenominator: s.rateDenominator, rules: s.rules, pullCount: s.pullCount, results: [] };
        const rrr = gachaResolver.resolve(grec);
        grec.combinedSeed = rrr.combined; grec.results = rrr.results; grec.tier = 'green';
        grec.commitmentHash = s.commitmentHash;
        grec.commitmentAnchor = { kind: 'rfc3161', commitmentHash: s.commitmentHash, genTime: s.genTime, roundRule: s.roundRule,
          tsa: s.anchor.tokens.map(t => t.tsa).join('+'), tokens: s.anchor.tokens };
        await store.putGacha(sessionId, Object.assign({}, s, { revealed: true, record: grec, revealedAt: now }));
        return res.json(grec);
      }
      if (typeof clientSeed !== 'string' || !clientSeed.trim()) return res.status(400).json({ error: 'need clientSeed (non-empty string)' });
      const rec = { branch: 'uvGacha', commitment: s.commitment, serverSeed: s.serverSeed, clientSeed: clientSeed.trim(),
        rateDenominator: s.rateDenominator, rules: s.rules, pullCount: s.pullCount, results: [] };
      const r = gachaResolver.resolve(rec);
      rec.combinedSeed = r.combined; rec.results = r.results; rec.tier = 'yellow';
      try {                                                                                   // 🟡 notary (existence-at-time), best-effort
        const recordHash = sha256(UVSCore.canonicalJSON(rec));
        const a = await rfc.stamp(recordHash, TSAS, { openssl: OPENSSL });
        rec.recordHash = recordHash;
        rec.notary = { kind: 'rfc3161', tsa: a.tokens.map(t => t.tsa).join('+'), tokens: a.tokens };
      } catch (e) { rec.notary = null; }
      await store.putGacha(sessionId, Object.assign({}, s, { revealed: true, record: rec, revealedAt: Math.floor(Date.now() / 1000) }));
      res.json(rec);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── uvGacha batch (🟢): the whole pull-session binds to a FUTURE drand round before its randomness exists
  // (uvGacha §6). clientSeed is fixed now; serverSeed is committed and ×2 RFC-3161-stamped before the round,
  // so genTime < timeOfRound(R) by construction. Poll /gacha/reveal { sessionId } after roundTime to settle 🟢.
  app.post('/gacha/commit-batch', async (req, res) => {
    try {
      const { rules, rateDenominator, pullCount, clientSeed, delaySeconds } = req.body || {};
      const D = rateDenominator;
      if (!rules || !Array.isArray(rules.tiers)) return res.status(400).json({ error: 'need rules.tiers[]' });
      try { gachaResolver.validateRules(rules, D); } catch (e) { return res.status(400).json({ error: e.message }); }
      const n = parseInt(pullCount);
      if (!Number.isInteger(n) || n < 1 || n > 1000) return res.status(400).json({ error: 'pullCount must be an integer 1..1000' });
      if (typeof clientSeed !== 'string' || !clientSeed.trim()) return res.status(400).json({ error: 'need clientSeed (fixed before the future round)' });
      const cs = clientSeed.trim();
      let delay = Number(delaySeconds) || 0;
      if (delay > 0) delay = Math.max(MIN_DELAY_S, Math.min(delay, MAX_DELAY_S));
      const serverSeed = crypto.randomBytes(32).toString('hex');
      const commitment = sha256(serverSeed);
      const chainHash = drand.QUICKNET.chainHash;
      let round, roundRule, commitmentRecord;
      if (delay > 0) {
        round = drand.roundAt(Math.floor(Date.now() / 1000) + delay) + 1;
        roundRule = 'explicit-R';
        commitmentRecord = { rules, rateDenominator: D, pullCount: n, clientSeed: cs, commitment, chainHash, round };
      } else {
        roundRule = 'roundAt(genTime)+1';
        commitmentRecord = { rules, rateDenominator: D, pullCount: n, clientSeed: cs, commitment, chainHash };
      }
      const commitmentHash = sha256(UVSCore.canonicalJSON(commitmentRecord));
      let anchor;
      try { anchor = await rfc.stamp(commitmentHash, TSAS, { openssl: OPENSSL }); }
      catch (e) { return res.status(502).json({ error: 'TSA stamping failed: ' + e.message }); }
      const genTime = Math.max.apply(null, anchor.tokens.map(t => t.genTime));
      if (delay === 0) round = drand.roundAt(genTime) + 1;
      const roundTime = drand.timeOfRound(round);
      if (genTime >= roundTime) return res.status(500).json({ error: 'stamp landed at/after target round — retry' + (delay ? ' with a larger delaySeconds' : '') });
      const sessionId = crypto.randomBytes(8).toString('hex');
      await store.putGacha(sessionId, { batch: true, serverSeed, commitment, clientSeed: cs, rateDenominator: D, rules, pullCount: n,
        round, roundTime, genTime, roundRule, commitmentHash, anchor, committedAt: Math.floor(Date.now() / 1000), revealed: false });
      res.json({ sessionId, commitment, round, roundTime, roundRule, commitmentHash, commitmentAnchor: anchor,
        note: 'uvGacha batch (🟢): session bound to a future drand round before its randomness exists. Poll /gacha/reveal { sessionId } after roundTime.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
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
    ok: true, tsas: TSAS.map(t => t.name), roundRule: 'roundAt(genTime)+1', twoPhase: true,
    ots: ots.available(), ca: caState,
    store: store.mode,
    autoReveal: { enabled: true, tickMs: REVEAL_TICK_MS,
      note: 'autonomous reveal depends on the keep-alive ping (event loop suspends when the host is idle); durability is ' + (store.mode === 'firestore' ? 'Firestore (durable)' : 'STATE_DIR files (ephemeral)') }
  }));

  return { tsas: TSAS.map(t => t.name), caFile: TSA_CA, host, store,
           _performReveal: performReveal, _revealTick: revealTick };
}

module.exports = { mountAnchoredDraws };
