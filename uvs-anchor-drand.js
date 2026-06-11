/* ============================================================================
 * UVS anchor module — drand (League of Entropy public randomness beacon).
 *
 * Turns the trust tier from 🟡 (self/unanchored) toward 🟢 by binding a game
 * record to a PUBLIC, independent, time-stamped randomness round that anyone can
 * re-fetch from any drand mirror. Two uses:
 *
 *   drandAnchor(cfg)   -> host anchor module { anchor(record) }: attaches a
 *                         verifiable drand round to the record (existence/time
 *                         anchor — proves the record is bound to a public round).
 *   futureRound(...)   -> the anti-grinding pattern: pick a round that has NOT
 *                         been published yet, so the operator cannot pre-pick
 *                         seeds. The outcome seed derives from that round's
 *                         randomness once it appears. (Used by the demo / v3.)
 *
 * randomness = SHA-256(signature bytes). We do NOT verify the BLS signature here
 * (needs a pairing lib); trust comes from re-fetching the round from the public
 * drand network. quicknet: 3s period.
 * ========================================================================== */
'use strict';

const QUICKNET = {
  beacon: 'quicknet', period: 3, genesis: 1692803367,
  chainHash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  base: 'https://api.drand.sh/v2/beacons/quicknet'
};

// time <-> round (drand round 1 is at genesis_time)
function roundAt(unixSec, info) { info = info || QUICKNET; return Math.floor((unixSec - info.genesis) / info.period) + 1; }
function timeOfRound(round, info) { info = info || QUICKNET; return info.genesis + (round - 1) * info.period; }

// randomness = SHA-256(signature bytes). hashBytes(hexStr) -> hex digest of those bytes.
function randomnessOf(signatureHex, hashBytes) { return hashBytes(signatureHex); }

async function fetchRound(round, cfg) {
  const info = cfg.info || QUICKNET;
  const base = cfg.base || info.base;
  const url = base + '/rounds/' + round;
  const j = await (await cfg.fetch(url)).json();
  const randomness = j.randomness || (cfg.hashBytes ? cfg.hashBytes(j.signature) : null);
  return { round: j.round, signature: j.signature, randomness, time: timeOfRound(j.round, info), url };
}

// Host anchor module: existence/time anchor to a public drand round.
function drandAnchor(cfg) {
  cfg = cfg || {};
  const info = cfg.info || QUICKNET;
  const base = cfg.base || info.base;
  const hashBytes = cfg.hashBytes;
  return {
    async anchor(record) {
      const j = await (await cfg.fetch(base + '/rounds/latest')).json();
      const randomness = j.randomness || (hashBytes ? hashBytes(j.signature) : null);
      return {
        source: 'drand', beacon: info.beacon, chainHash: info.chainHash,
        round: j.round, randomness, signature: j.signature,
        roundTime: timeOfRound(j.round, info),
        verifyUrl: 'https://api.drand.sh/' + info.chainHash + '/public/' + j.round,
        note: 'Re-fetch verifyUrl from any drand mirror; randomness = SHA-256(signature). Round time is external and unforgeable.'
      };
    }
  };
}

// Anti-grinding: a round that has NOT been published yet at `unixNow`.
function futureRound(unixNow, aheadSeconds, info) {
  info = info || QUICKNET;
  const cur = roundAt(unixNow, info);
  const ahead = Math.max(1, Math.ceil((aheadSeconds || 9) / info.period));
  const round = cur + ahead;
  return { round, time: timeOfRound(round, info) };
}

module.exports = { QUICKNET, roundAt, timeOfRound, randomnessOf, fetchRound, drandAnchor, futureRound };
