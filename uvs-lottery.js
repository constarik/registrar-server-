/* ============================================================================
 * UVS uvLottery plugin (the "L" branch) — verifiable draws on the UVS host.
 *
 * A draw is NOT a game: no player, no clientSeed, no ChaCha20 keystream. It is
 * ONE seeded permutation of the participants + a published pool dealt onto it.
 *
 *   combinedSeed = SHA-256( serverSeed + ":" + drandRandomness )
 *   score(id)    = SHA-256( combinedSeed + ":" + id )
 *   order        = participants sorted by score DESC  (ties: id ASC)
 *   allocation   = order[i] receives prizes[i]   (null beyond the pool)
 *
 * drand lives INSIDE this module (the lottery owns its randomness source); its
 * failure cannot take down the game plugins on the same host.
 *
 * Conforms to uvLs.md (uvLottery Standard v3). Reproduces verifiers/test-vectors.json
 * byte-for-byte. Plug in with:  host.use(makeLottery({ sha256, name:'lottery' }))
 * ========================================================================== */
'use strict';

const drand = require('./uvs-anchor-drand.js');

function makeLottery(opts) {
  opts = opts || {};
  const sha256 = opts.sha256;
  if (typeof sha256 !== 'function') throw new Error('makeLottery needs { sha256 }');

  const combinedSeed = (serverSeed, randomness) => sha256(serverSeed + ':' + randomness);
  const scoreOf      = (combined, id) => sha256(combined + ':' + id);

  // deterministic total order: highest score first, ties broken by id ascending
  function cmp(a, b) {
    if (a.score > b.score) return -1;
    if (a.score < b.score) return 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  }
  // uvLs §3.1: duplicate ids break the total order — reject, don't rank (audit A3).
  function requireUnique(participants) {
    if (new Set(participants).size !== participants.length)
      throw new Error('INVALID: duplicate participant ids — record rejected (uvLs §3.1)');
  }
  function permute(participants, combined) {
    requireUnique(participants);
    return participants.map(id => ({ id, score: scoreOf(combined, id) })).sort(cmp);
  }
  // full allocation: each position in the permutation receives prizes[i]
  function allocate(participants, combined, prizes) {
    return permute(participants, combined).map((p, i) => ({
      rank: i + 1, id: p.id, prize: i < prizes.length ? prizes[i] : null, score: p.score
    }));
  }
  // single lookup — O(M) hashing, no sort (a participant checks only their own id)
  function lookup(participants, combined, id, prizes) {
    requireUnique(participants);
    const me = scoreOf(combined, id);
    let higher = 0, present = false;
    for (const a of participants) {
      if (a === id) { present = true; continue; }
      const s = scoreOf(combined, a);
      if (s > me || (s === me && a < id)) higher++;
    }
    const rank = higher + 1;
    return { id, present, rank, prize: present && rank <= prizes.length ? prizes[rank - 1] : null, score: me };
  }
  // build the prize pool from rules: explicit prizes[], or prizePool[{tier,key,count}], or {winners,prizeLabel}
  function poolOf(rules) {
    rules = rules || {};
    if (Array.isArray(rules.prizes)) return rules.prizes.slice();
    if (Array.isArray(rules.prizePool)) {
      const out = [];
      for (const e of rules.prizePool) {
        const label = e.key || e.tier || 'WIN';
        for (let i = 0; i < (e.count || 0); i++) out.push(label);
      }
      return out;
    }
    const n = rules.winners || rules.N || 0;
    return Array.from({ length: n }, () => rules.prizeLabel || 'WIN');
  }

  return {
    name: opts.name || 'lottery',
    profile: 'draw',
    draw: {
      combinedSeed, scoreOf, permute, allocate, lookup, poolOf,
      timeOfRound: (r) => drand.timeOfRound(r),
      futureRound: (nowSec, ahead) => drand.futureRound(nowSec, ahead),
      QUICKNET: drand.QUICKNET
    }
  };
}

module.exports = { makeLottery };
