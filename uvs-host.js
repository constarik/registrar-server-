/* ============================================================================
 * UVS Host — composable backend. NO privileged core.
 *
 * The ONLY fixed point is the deterministic engine + adapter contract.
 * Everything else is an OPTIONAL module the operator plugs in (or omits):
 *   seed     : { issue() -> uint32, derive(regSeed, gameSeed) -> {serverSeed} }
 *              the commit-reveal authority (a.k.a. "the registrar"). OPTIONAL.
 *   storage  : { put(id,rec), get(id), list(limit) }   OPTIONAL (default: memory)
 *   anchor   : { anchor(record) -> proof }             OPTIONAL (drand/chain).
 *
 * Games are PLUGINS of two profiles:
 *   batch (G=ALL): { name, profile:'batch', adapter:{init,step,isFinished,result} }
 *   sync  (G=1):   { name, profile:'sync', mount(app, wss, services) }
 *
 * Compose:  createHost({sha256, seed?, storage?, anchor?}).use(paddla).use(noisore)
 * The trust TIER is DERIVED from which modules were actually present — not claimed.
 * ========================================================================== */
'use strict';

const UVSCore = require('./uvs-core.js');
const crypto = require('crypto');
const rfc3161 = require('./uvs-anchor-rfc3161.js');

// ---- §5.4 anchor verification: an anchor is EVIDENCE only if it VERIFIES. ----
// Presence of a `proof` field is not proof (audit A1). Every RFC 3161 token must
// verify over `commitmentHash` against the host-configured TSA CA bundle. Returns
// { ok, genTime?, verified?, reason? } — genTime is the LATEST verified token time
// (max), per §5.4.1: with multiple TSAs, every token must predate R, so the round
// rule is checked against max(genTime). Time/round checks live in the caller.
function verifyAnchor3161(ca, commitmentHash, tsaCfg) {
  if (!tsaCfg || !tsaCfg.caFile)
    return { ok: false, reason: 'host has no TSA CA configured (cfg.tsa.caFile) — anchor cannot be verified, tier stays amber' };
  const toks = Array.isArray(ca.tokens) ? ca.tokens
    : (ca.proof ? [{ tsa: ca.tsa || 'tsa', proof: ca.proof }] : []);
  if (!toks.length) return { ok: false, reason: 'no tokens in commitmentAnchor' };
  let maxGen = null, verified = 0;
  for (const t of toks) {
    try {
      const r = rfc3161.verify(commitmentHash, Buffer.from(String(t.proof), 'base64'), tsaCfg.caFile, tsaCfg.openssl || 'openssl');
      if (r.ok && r.genTime != null) { verified++; if (maxGen == null || r.genTime > maxGen) maxGen = r.genTime; }
    } catch (e) { /* this token failed; the next may still verify */ }
  }
  return verified ? { ok: true, genTime: maxGen, verified }
    : { ok: false, reason: 'no token verified over commitmentHash' };
}

// ---- optional module: in-memory storage (dev/tests). Swap for Firestore etc. ----
function memoryStorage() {
  const m = new Map();
  return {
    async put(id, rec) { m.set(id, rec); },
    async get(id) { return m.has(id) ? m.get(id) : null; },
    async list(limit) {
      return Array.from(m.values()).sort((a, b) => (b.ts || 0) - (a.ts || 0)).slice(0, limit || 20);
    }
  };
}

// ---- trust tier DERIVED from facts, never claimed (TLS self-signed analogy). ----
// Three anchor strengths (uvs.md §10.2): notary < trail-immutability < outcome-binding.
function deriveTier(f) {
  f = f || {};
  // 🟢: a valid neutral-registry signature, OR a trail-immutability inclusion proof, OR
  //     outcome-binding WHOSE commitment-priority is itself proven (uvs §10, uvLs §5.4).
  //     A future drand round alone is NOT green — without proof the commitment preceded it,
  //     the operator could backdate the commitment and grind (uvs §12.2 "commitment backdating").
  if (f.neutralSig) return 'green';
  if (f.trailImmutable) return 'green';
  if (f.outcomeBound && f.commitmentAnchored) return 'green';
  // 🟡: an anchor exists (notary, self-anchored, seed authority, or outcome-binding without a
  //     proven commitment) but none of the 🟢 conditions hold.
  if (f.anchored || f.outcomeBound || f.seedAuthority || f.neutralHost) return 'amber';
  return 'red';                                                          // self/client seed, unanchored
}

function createHost(cfg) {
  cfg = cfg || {};
  const sha256 = cfg.sha256;                       // (str)->hex  (needed for verify/trail ids)
  const versions = cfg.versions || [1];
  const storage = cfg.storage || memoryStorage();  // optional module
  const seed = cfg.seed || null;                   // optional: registrar / commit-reveal authority
  const anchor = cfg.anchor || null;               // optional: drand/chain anchor
  const tsa = cfg.tsa || null;                     // optional: { caFile, openssl? } — §5.4 anchor verification (without it no draw reaches 🟢)
  const neutralHost = !!cfg.neutralHost;           // operator-declared: neutral registry vs self-host
  const defaultGame = cfg.defaultGame || null;     // back-compat: assume this game when a client omits `game`
  const trailPath = cfg.trailPath || '/trail';
  const sessionTtlMs = cfg.sessionTtlMs || 10 * 60 * 1000;
  const games = new Map();                          // name -> plugin
  const sessions = new Map();
  function gc() { const now = Date.now(); for (const [k, v] of sessions) if (now - v.created > sessionTtlMs) sessions.delete(k); }

  const host = {
    storage, supportedVersions: versions,

    // Register a game plugin (batch adapter or sync mount). Chainable.
    use(plugin) {
      if (!plugin || !plugin.name) throw new Error('plugin needs a name');
      const profile = plugin.profile || 'batch';
      if (profile === 'batch' && !plugin.adapter) throw new Error('batch plugin "' + plugin.name + '" needs an adapter');
      if (profile === 'sync' && typeof plugin.mount !== 'function') throw new Error('sync plugin "' + plugin.name + '" needs mount()');
      if (profile === 'draw' && !plugin.draw) throw new Error('draw plugin "' + plugin.name + '" needs a draw module (uvLottery)');
      games.set(plugin.name, Object.assign({ profile }, plugin));
      return host;
    },
    games() { return Array.from(games.values()).map(g => ({ name: g.name, profile: g.profile })); },

    // POST /session/new  { game, gameSeed, versions }
    newSession(game, body) {
      gc();
      const g = games.get(game);
      if (!g) return { accepted: false, error: 'unknown game ' + game };
      const negotiated = UVSCore.negotiateVersion(body.versions || [1], versions);
      if (!negotiated) return { accepted: false, serverVersions: versions };
      const sessionId = crypto.randomBytes(8).toString('hex');
      const regSeed = seed ? (seed.issue() >>> 0) : null;   // seed module optional
      sessions.set(sessionId, { game, regSeed, gameSeed: (body.gameSeed >>> 0), uvsVersion: negotiated, created: Date.now() });
      return { accepted: true, negotiated, serverVersions: versions, sessionId, regSeed,
               seedAuthority: !!seed, expiresIn: sessionTtlMs / 1000 };
    },

    // POST /verify/:game  { regSeed?, serverSeed?, gameSeed, inputLog, clientResult, params, mode }
    async verify(game, body) {
      const g = games.get(game);
      if (!g) return { ok: false, error: 'unknown game ' + game };
      if (g.profile !== 'batch') return { ok: false, error: 'verify is for batch games; ' + game + ' is ' + g.profile };
      if (body.gameSeed == null || !Array.isArray(body.inputLog)) return { ok: false, error: 'missing fields' };

      // Resolve serverSeed: neutral commit (seed module) OR client-claimed (lower trust).
      let serverSeed, seedAuthority;
      if (seed && body.regSeed != null) {
        serverSeed = (await seed.derive(body.regSeed >>> 0, body.gameSeed >>> 0)).serverSeed; seedAuthority = true;
      } else if (body.serverSeed) {
        serverSeed = body.serverSeed; seedAuthority = false;
      } else {
        return { ok: false, error: 'no serverSeed: send regSeed (needs seed module) or serverSeed' };
      }

      const params = body.params || {};
      let state = g.adapter.init(serverSeed, params), i = 0, guard = 0;
      while (!g.adapter.isFinished(state) && guard < 1000000) {
        const inp = body.inputLog[i]; g.adapter.step(state, inp ? inp.target : null); i++; guard++;
      }
      const serverResult = g.adapter.result(state);
      const ok = JSON.stringify(serverResult) === JSON.stringify(body.clientResult);

      let gameId = null, tier = null;
      if (ok) {
        const compressed = UVSCore.compressInputLog(body.inputLog);
        // uvGs §10.3: gameId = SHA-256(serverSeed : SHA-256(JSON(compressedInputLog))) — PLAIN
        // JSON bytes, not canonical JSON: Move targets are floats (quantized by the engine at
        // consumption, §3.5), and canonical JSON is integer-only by design (core §5). The recipe
        // hash needs stable bytes, and JS JSON number formatting is ECMA-mandated shortest-round-trip.
        const inputHash = sha256(JSON.stringify(compressed));
        gameId = sha256(serverSeed + ':' + inputHash);
        const record = {
          gameId, game, branch: 'uvGame', uvsVersion: 3, protocol: 'UVS-3.0', granularity: 'ALL',
          regSeed: body.regSeed != null ? (body.regSeed >>> 0) : null, gameSeed: body.gameSeed >>> 0,
          serverSeed, commitment: sha256(serverSeed),
          params, mode: body.mode || null, result: serverResult, ticks: i,
          inputLen: body.inputLog.length, inputLog: compressed, ts: Date.now()
        };
        let anchorProof = null;
        if (anchor) { try { anchorProof = await anchor.anchor(record); } catch (e) { anchorProof = null; } }
        record.anchorProof = anchorProof;
        record.tierFacts = { seedAuthority, anchored: !!anchorProof, neutralHost };
        tier = deriveTier(record.tierFacts);
        record.tier = tier;
        await storage.put(gameId, record);
      }
      return { ok, serverResult, clientResult: body.clientResult, gameId, tier,
               trailUrl: gameId ? trailPath + '/' + gameId : null };
    },

    // POST /draw/:name  { serverSeed, commitment?, commitTime?, drand:{round,randomness}, participants, rules, model }
    // uvLottery (the "L" branch): one seeded permutation. Born at v3, no version negotiation.
    async draw(name, body) {
      const g = games.get(name);
      if (!g) return { ok: false, error: 'unknown draw ' + name };
      if (g.profile !== 'draw') return { ok: false, error: 'draw is for draw plugins; ' + name + ' is ' + g.profile };
      if (!body.serverSeed || !body.drand || body.drand.randomness == null || !Array.isArray(body.participants))
        return { ok: false, error: 'missing fields (serverSeed, drand.randomness, participants)' };
      // uvLs §3.1 (audit A3): duplicate ids break the total order — reject, don't rank.
      if (new Set(body.participants).size !== body.participants.length)
        return { ok: false, error: 'INVALID: duplicate participant ids — record rejected (uvLs §3.1)' };
      const D = g.draw;
      const combinedSeed = D.combinedSeed(body.serverSeed, body.drand.randomness);
      const prizes = D.poolOf(body.rules || {}, body.participants.length);   // §6.1: resolve proportional tiers against M
      const result = D.allocate(body.participants, combinedSeed, prizes);
      const commitment = body.commitment || sha256(body.serverSeed);
      // tier DERIVED, not claimed: outcome-bound iff the drand round publishes AFTER the commit
      // (future round = anti-grind). A past/concurrent round is only a notary -> amber.
      const roundTime = body.drand.round != null ? D.timeOfRound(body.drand.round) : null;
      // §5.4 (audit A1/A2): the anchor must VERIFY to count toward 🟢, and the commit time the
      // tier rests on is the VERIFIED token genTime — never the caller's claimed commitTime.
      // Binding (two §5.4 forms): the commitment record is canonicalJSON of
      //   derived-R (§5.4.1):  { chainHash, commitment, participants, prizePool }   (no round)
      //   explicit-R:          { chainHash, commitment, participants, prizePool, round }
      // For derived-R the round rule R == roundAt(maxGenTime)+1 MUST also hold.
      let commitmentAnchored = false, anchorCheck = null;
      let commitTime = body.commitTime != null ? body.commitTime : null;
      let commitTimeSource = commitTime != null ? 'claimed' : null;
      if (body.commitmentAnchor && roundTime != null) {
        // prizePool in the commitment record is the DECLARED pool (rules.prizePool, or the rules
        // object itself) — exactly as /commit hashed it, NOT the expanded prizes array.
        const poolDecl = (body.rules && body.rules.prizePool) || body.rules || {};
        const base = { chainHash: D.QUICKNET.chainHash, commitment, participants: body.participants, prizePool: poolDecl };
        const expectedDerived = sha256(UVSCore.canonicalJSON(base));
        const expectedExplicit = sha256(UVSCore.canonicalJSON(Object.assign({ round: body.drand.round }, base)));
        const form = body.commitmentAnchor.commitmentHash === expectedDerived ? 'derived'
                   : body.commitmentAnchor.commitmentHash === expectedExplicit ? 'explicit' : null;
        if (!form) {
          anchorCheck = { ok: false, reason: 'commitmentHash does not bind this draw (neither §5.4 form matches)' };
        } else {
          anchorCheck = verifyAnchor3161(body.commitmentAnchor, body.commitmentAnchor.commitmentHash, tsa);
          if (anchorCheck.ok) {
            const g2 = anchorCheck.genTime;
            const rAt = Math.floor((g2 - D.QUICKNET.genesis) / D.QUICKNET.period) + 1;
            const timeOk = g2 < roundTime;
            const ruleOk = form === 'explicit' ? timeOk : (body.drand.round === rAt + 1 && timeOk);
            if (ruleOk) anchorCheck.form = form;
            else anchorCheck = { ok: false, genTime: g2, form, reason: form === 'derived'
              ? '§5.4.1 round rule failed: R must equal roundAt(maxGenTime)+1 and genTime < timeOfRound(R)'
              : '§5.4: genTime is not before timeOfRound(R)' };
          }
        }
        if (anchorCheck.ok) { commitmentAnchored = true; commitTime = anchorCheck.genTime; commitTimeSource = 'tsa-genTime'; }
      }
      const outcomeBound = roundTime != null && commitTime != null && roundTime > commitTime;
      const facts = { anchored: body.drand.round != null, outcomeBound, commitmentAnchored, neutralHost };
      const tier = deriveTier(facts);
      const drawId = sha256(body.serverSeed + ':' + combinedSeed + ':' + sha256(UVSCore.canonicalJSON(body.participants)));
      const record = {
        gameId: drawId, branch: 'uvLottery', uvsVersion: 3, schema: 'verifiable-allocation/v1',
        protocol: 'UVS-3.0', game: name, model: body.model || null,
        serverSeed: body.serverSeed, commitment,
        drand: {
          beacon: D.QUICKNET.beacon, chainHash: D.QUICKNET.chainHash, round: body.drand.round,
          randomness: body.drand.randomness, roundTime,
          verifyUrl: body.drand.round != null ? 'https://api.drand.sh/' + D.QUICKNET.chainHash + '/public/' + body.drand.round : null
        },
        combinedSeed, participants: body.participants, rules: body.rules || {}, result,
        commitmentAnchor: body.commitmentAnchor || null,   // §5.4 evidence; must VERIFY for 🟢
        anchorCheck: anchorCheck,                          // { ok, genTime?, reason? } — why the tier is what it is
        commitTime, commitTimeSource,                      // 'tsa-genTime' (verified) | 'claimed' (operator's word)
        tierFacts: facts, tier, ts: Date.now()
      };
      await storage.put(drawId, record);
      // anchorCheck/commitTimeSource travel with the response so the published record can
      // carry the host's verification verdict, not just the tier it produced (audit A1 follow-up).
      return { ok: true, drawId, combinedSeed, result, tier, anchorCheck, commitTimeSource, trailUrl: trailPath + '/' + drawId };
    },

    // POST /draw/:name/verify — recompute a draw record from scratch and compare the order
    async verifyDraw(name, record) {
      const g = games.get(name);
      if (!g || g.profile !== 'draw') return { ok: false, error: 'unknown draw ' + name };
      const D = g.draw;
      const participants = Array.isArray(record && record.participants) ? record.participants
        : (record && record.rules && Array.isArray(record.rules.participants) ? record.rules.participants : null);
      if (!record || !record.serverSeed || !record.drand || participants == null)
        return { ok: false, error: 'record needs serverSeed, drand.randomness, participants' };
      const combinedSeed = D.combinedSeed(record.serverSeed, record.drand.randomness);
      const prizes = D.poolOf(record.rules || {}, participants.length);   // §6.1: resolve proportional tiers against M
      const result = D.allocate(participants, combinedSeed, prizes);
      const norm = (r) => JSON.stringify((r || []).map(x => [x.rank, x.id, x.prize]));
      const ok = combinedSeed === record.combinedSeed && norm(result) === norm(record.result);
      return { ok, combinedSeed, result };
    },

    getTrail(id) { return storage.get(id); },
    listTrail(limit) { return storage.list(limit); },

    // Wire the standard routes into an Express app. wss (optional) is passed to sync plugins.
    mountExpress(app, wss) {
      // `defaultGame` keeps legacy clients working: they hit /session/new and
      // /verify/<game> without a `game` body field. /verify/:game already matches
      // the legacy /verify/paddla path, so no route is broken on deploy.
      app.post('/session/new', (req, res) => res.json(host.newSession(req.body.game || defaultGame, req.body)));
      app.post('/verify/:game', async (req, res) => {
        try { res.json(await host.verify(req.params.game, req.body)); }
        catch (e) { res.status(500).json({ error: e.message }); }
      });
      // uvLottery (draw) routes — same host, different path (one server, /verify + /draw).
      app.post('/draw/:name', async (req, res) => {
        try { res.json(await host.draw(req.params.name, req.body)); }
        catch (e) { res.status(500).json({ error: e.message }); }
      });
      app.post('/draw/:name/verify', async (req, res) => {
        try { res.json(await host.verifyDraw(req.params.name, req.body.record || req.body)); }
        catch (e) { res.status(500).json({ error: e.message }); }
      });
      app.get(trailPath, async (req, res) => {
        const items = await host.listTrail(Math.min(parseInt(req.query.limit) || 20, 100));
        res.json({ count: items.length, items: items.map(x => ({ gameId: x.gameId, branch: x.branch || 'uvGame', game: x.game, result: x.result, tier: x.tier, ts: x.ts })) });
      });
      app.get(trailPath + '/:id', async (req, res) => {
        const r = await host.getTrail(req.params.id); r ? res.json(r) : res.status(404).json({ error: 'not found' });
      });
      // sync plugins (e.g. NOISORE) mount their own realtime endpoints, using host services.
      const services = { seed, storage, sha256, anchor, deriveTier, core: UVSCore, sessions };
      for (const g of games.values()) if (g.profile === 'sync') g.mount(app, wss, services);
      return app;
    }
  };
  return host;
}

module.exports = { createHost, memoryStorage, deriveTier };
