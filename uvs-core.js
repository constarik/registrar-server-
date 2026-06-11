/* ============================================================================
 * UVS Core — pure protocol primitives (engine-independent, no I/O)
 * Shared by client and server. UVS v2.
 * ========================================================================== */
(function (root) {
  'use strict';

  // Version negotiation: integer sets. Returns the highest common version, or null.
  // (Sets, not ranges, so a broken version can be explicitly excluded.)
  function negotiateVersion(clientVersions, serverVersions) {
    const common = clientVersions.filter(v => serverVersions.includes(v));
    return common.length ? Math.max.apply(null, common) : null;
  }

  // Delta-encode a dense per-tick inputLog [{tick,target}] -> sparse [{t,target}]
  // keeping only ticks where the input changed. Keeps audit records tiny.
  function compressInputLog(inputLog) {
    if (!Array.isArray(inputLog)) return [];
    const out = []; let last = ' ';
    for (let i = 0; i < inputLog.length; i++) {
      const tgt = inputLog[i] && inputLog[i].target ? inputLog[i].target : null;
      const key = tgt ? (tgt.x + ',' + tgt.y) : ' ';
      if (key !== last) { out.push({ t: i, target: tgt }); last = key; }
    }
    return out;
  }

  // Inverse: rebuild the dense per-tick target array of length `len`.
  function expandInputLog(compressed, len) {
    const dense = []; let cur = null, ci = 0;
    const comp = Array.isArray(compressed) ? compressed : [];
    for (let i = 0; i < len; i++) {
      while (ci < comp.length && comp[ci].t === i) { cur = comp[ci].target; ci++; }
      dense.push({ tick: i, target: cur });
    }
    return dense;
  }

  // Canonical JSON for hashing: keys sorted by Unicode CODE POINT, no whitespace,
  // strings NFC-normalized. Numbers MUST be integers (no float ambiguity) — enforced.
  //
  // Audit A6: JS default string sort compares UTF-16 code units, which disagrees with
  // code-point order for astral-plane characters (a surrogate 0xD800.. sorts below
  // 0xE000..0xFFFF, but its code point is higher). Compare by code points explicitly
  // so JS, Python (sorted()), Java and C++ all hash identical bytes.
  function cmpCodePoint(a, b) {
    const A = Array.from(a), B = Array.from(b);     // iterate by code points, not units
    const n = Math.min(A.length, B.length);
    for (let i = 0; i < n; i++) {
      const x = A[i].codePointAt(0), y = B[i].codePointAt(0);
      if (x !== y) return x - y;
    }
    return A.length - B.length;
  }
  function canonicalJSON(v) {
    if (v === null || typeof v !== 'object') {
      if (typeof v === 'string') return JSON.stringify(v.normalize('NFC'));
      if (typeof v === 'number' && !Number.isInteger(v))
        throw new Error('canonicalJSON: non-integer number ' + v + ' — hashable values must be integers (quantize floats first, core §5)');
      return JSON.stringify(v);
    }
    if (Array.isArray(v)) return '[' + v.map(canonicalJSON).join(',') + ']';
    const pairs = Object.keys(v).map(k => [k.normalize('NFC'), v[k]])   // normalize keys, keep values paired
      .sort((a, b) => cmpCodePoint(a[0], b[0]));
    return '{' + pairs.map(p => JSON.stringify(p[0]) + ':' + canonicalJSON(p[1])).join(',') + '}';
  }

  const api = { negotiateVersion, compressInputLog, expandInputLog, canonicalJSON };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.UVSCore = api;
})(typeof window !== 'undefined' ? window : this);
