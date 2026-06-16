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
  // §6.1 proportional resolution — a tier's count as an integer num/den of the participant count M,
  // one rounding mode. All-integer (BigInt) so it matches the JS/Python/Java/C++ reference verifiers
  // byte-for-byte; operands non-negative ⇒ division is floor.
  function resolveCount(M, rule) {
    const num = rule.num, den = rule.den, mode = rule.mode || 'round-half-up';
    if (!Number.isInteger(num) || !Number.isInteger(den) || !Number.isInteger(M) || den <= 0 || num < 0 || M < 0)
      throw new Error('INVALID: proportional num/den/M must be non-negative integers with den>0 (uvLs §6.1)');
    const Mb = BigInt(M), n = BigInt(num), d = BigInt(den);
    let c;
    if (mode === 'floor') c = (Mb * n) / d;
    else if (mode === 'ceil') c = (Mb * n + d - 1n) / d;
    else if (mode === 'round-half-up') c = (2n * Mb * n + d) / (2n * d);
    else throw new Error('INVALID: unknown rounding mode "' + mode + '" (uvLs §6.1)');
    return Number(c);
  }

  // build the prize pool from rules: explicit prizes[]; prizePool[{tier,key,count|rule}] (a §6.1 rule
  // resolves against M = participant count, clamped so the running total never exceeds M); or {winners,prizeLabel}
  function poolOf(rules, M) {
    rules = rules || {};
    if (Array.isArray(rules.prizes)) return rules.prizes.slice();
    if (Array.isArray(rules.prizePool)) {
      M = (typeof M === 'number') ? M : 0;
      const out = [];
      let total = 0;
      for (const e of rules.prizePool) {
        const label = e.key || e.tier || 'WIN';
        let count;
        if (e.rule) {
          count = resolveCount(M, e.rule);
          if (e.count != null && e.count !== count)
            throw new Error('INVALID: tier "' + label + '" count ' + e.count + ' != rule-resolved ' + count + ' (uvLs §6.1)');
        } else {
          count = e.count || 0;
        }
        if (M && total + count > M) count = M - total;   // §6.1 ordering: clamp running total to M
        if (count < 0) count = 0;
        for (let i = 0; i < count; i++) out.push(label);
        total += count;
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
