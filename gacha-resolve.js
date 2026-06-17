/* ============================================================================
 * UVS uvGacha — REFERENCE RESOLVER (Node.js, stdlib only)
 *
 * A gacha session is a deterministic resolver replayed over committed entropy
 * (uvGacha §2). Per pull i:
 *   combinedSeed = SHA-256( serverSeed : clientSeed : drandRandomness )
 *   u_i          = SHA-256( combinedSeed : i )  as a 256-bit big-endian int, mod D
 *   outcome      = the tier whose cumulative integer interval in [0,D) contains u_i
 * Optional stateful pity (uvGacha §5) is a deterministic function of prior pulls,
 * RECONSTRUCTED by replay from pull 1 — never stored (core §6.1, the recipe principle).
 *
 * Integer arithmetic uses BigInt (uvGacha §4 / uvLottery §6.1 width discipline) so JS
 * matches a big-integer language byte-for-byte. Mirrors gacha_resolve.py and reproduces
 * verifiers/test-vectors-gacha.json.
 *
 * Run:  node gacha-resolve.js <record.json>    (resolve a session)
 *       node gacha-resolve.js                   (self-test against the vectors)
 * ========================================================================== */
'use strict';
const crypto = require('crypto');
const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

function combinedSeed(serverSeed, clientSeed, drandRandomness) {
  return sha256(serverSeed + ':' + clientSeed + ':' + (drandRandomness || ''));
}

// u_i = SHA-256(combinedSeed:i) as a 256-bit big-endian integer, mod D  (BigInt: no overflow)
function pullValue(combined, i, D) {
  return Number(BigInt('0x' + sha256(combined + ':' + i)) % BigInt(D));
}

// rates MUST be JSON integers and sum to exactly D; reject otherwise (uvGacha §4)
function validateRules(rules, D) {
  if (!Number.isInteger(D) || D <= 0) throw new Error('INVALID: rateDenominator must be a positive integer (uvGacha §4)');
  let sum = 0;
  for (const t of rules.tiers) {
    if (typeof t.tier !== 'string') throw new Error('INVALID: tier label must be a string (uvGacha §4)');
    if (!Number.isInteger(t.rate) || t.rate < 0) throw new Error('INVALID: rate must be a non-negative integer (uvGacha §4)');
    sum += t.rate;
  }
  if (sum !== D) throw new Error('INVALID: tier rates sum to ' + sum + ' != rateDenominator ' + D + ' (uvGacha §4)');
}

// the tier whose cumulative interval contains u (tiers in their declared order)
function tierOf(tiers, u) {
  let acc = 0;
  for (const t of tiers) { acc += t.rate; if (u < acc) return t.tier; }
  throw new Error('INVALID: u beyond cumulative range — rules do not cover D');
}

// resolve a whole session deterministically. rules.pity (optional) = { tier, hardAfter }:
// the §5 example machine — a guaranteed `tier` on the hardAfter-th consecutive pull without it.
function resolve(rec) {
  const D = rec.rateDenominator;
  validateRules(rec.rules, D);
  const combined = combinedSeed(rec.serverSeed, rec.clientSeed, rec.drand && rec.drand.randomness);
  const pity = rec.rules.pity || null;
  const results = [];
  let miss = 0;                                  // consecutive misses of the pity tier — reconstructed, not stored
  for (let i = 1; i <= rec.pullCount; i++) {
    const u = pullValue(combined, i, D);
    let tier, forced = false;
    if (pity && miss + 1 >= pity.hardAfter) { tier = pity.tier; forced = true; }
    else tier = tierOf(rec.rules.tiers, u);
    results.push({ i, tier, forced });
    miss = (pity && tier === pity.tier) ? 0 : miss + 1;
  }
  return { combined, results };
}

module.exports = { sha256, combinedSeed, pullValue, validateRules, tierOf, resolve };

// ---- CLI ----
if (require.main === module) {
  const fs = require('fs'), path = require('path');
  const file = process.argv[2];
  if (file) {
    const { combined, results } = resolve(JSON.parse(fs.readFileSync(file, 'utf8')));
    console.log('combinedSeed =', combined);
    results.forEach((r) => console.log('  pull ' + r.i + ': ' + r.tier + (r.forced ? '  (pity)' : '')));
  } else {
    const tv = JSON.parse(fs.readFileSync(path.join(__dirname, 'test-vectors-gacha.json'), 'utf8'));
    const A = resolve(tv.stateless.record);
    const aOk = A.combined === tv.stateless.combinedSeed && JSON.stringify(A.results.map((r) => r.tier)) === JSON.stringify(tv.stateless.tiers);
    const B = resolve(tv.pity.record);
    const bOk = B.combined === tv.pity.combinedSeed && JSON.stringify(B.results) === JSON.stringify(tv.pity.pulls);
    let neg = false;
    try { resolve(tv.negative['rates-not-sum-D'].record); } catch (e) { neg = true; }
    console.log('stateless', aOk, '| pity', bOk, '| rates-sum-reject', neg);
    console.log('gacha self-test', aOk && bOk && neg ? 'PASS' : 'FAIL');
  }
}
