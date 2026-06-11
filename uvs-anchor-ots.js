/* ============================================================================
 * UVS §5.4 second anchor — OpenTimestamps (Bitcoin trail-immutability).
 *
 * RFC 3161 is the PRIMARY §5.4 evidence: an immediate signed token whose genTime
 * fits the seconds-to-minutes commit→R window. OpenTimestamps is the FREE SECOND
 * anchor of a DIFFERENT kind: it submits the commitmentHash to public calendar
 * servers now and returns a PENDING proof that matures into a Bitcoin-block
 * inclusion proof in ~hours. Once confirmed it is trail-immutability evidence the
 * commitment existed by that block's time — independent of any TSA.
 *
 * Best-effort by contract: this NEVER throws fatally and the RFC-3161 green path
 * must not depend on it. If the library or the calendars are unavailable, the draw
 * is still 🟢 on the RFC-3161 tokens alone; OTS just upgrades the evidence later.
 * ========================================================================== */
'use strict';

let OTS = null;
try { OTS = require('opentimestamps'); }                 // maintained package name (0.4.6+)
catch (e) { try { OTS = require('javascript-opentimestamps'); } catch (e2) { OTS = null; } }

/**
 * Stamp a sha256 commitmentHash at the OpenTimestamps calendars.
 * @returns {Promise<{ ok, kind, status, proof(base64), note } | { ok:false, error }>}
 */
async function stamp(commitmentHashHex, opts) {
  opts = opts || {};
  if (!OTS) return { ok: false, error: 'opentimestamps not installed (optional second anchor)' };
  try {
    const { DetachedTimestampFile, Ops } = OTS;
    const digest = Buffer.from(commitmentHashHex, 'hex');           // commitmentHash IS a sha256 digest
    const detached = DetachedTimestampFile.fromHash(new Ops.OpSHA256(), digest);
    const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error('OTS calendar timeout')), opts.timeoutMs || 12000));
    await Promise.race([OTS.stamp(detached), timeout]);
    const bytes = detached.serializeToBytes();
    return {
      ok: true, kind: 'opentimestamps', status: 'pending-bitcoin',
      proof: Buffer.from(bytes).toString('base64'),
      note: 'Pending Bitcoin confirmation (~hours). Upgrade + verify with the OpenTimestamps client; ' +
            'matures into a blockchain trail-immutability anchor over the same commitmentHash.'
    };
  } catch (e) { return { ok: false, error: e.message }; }
}

module.exports = { stamp, available: () => !!OTS };
