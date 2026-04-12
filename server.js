/**
 * REGISTRAR SERVER v2.1.1 — Uncloned Math — UVS 1.0
 * 
 * Roles:
 *   1. Issues session seeds (regSeed → WASM → finalSeed)
 *   2. Verifies WASM computation
 *   3. Verifies PADDLA game results (full engine replay)
 */

const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const { createInitialState, tick: engineTick, sha256Hex } = require('paddla-engine');

const app  = express();
app.use(cors());
app.use(express.json({ limit: '5mb' })); // inputLog can be large

// ============================================================
// LCG — same as client (this is the "certified engine")
// ============================================================
class LCG {
  constructor(seed) { this.s = seed >>> 0; }
  next() { this.s = (Math.imul(this.s, 1664525) + 1013904223) >>> 0; return this.s; }
  range(lo, hi) { return lo + (this.next() % (hi - lo)); }
}

const BINARY_OPS = [0x6a,0x6b,0x6c,0x73]; // add,sub,mul,xor — no AND/OR bias
const SHIFT_OPS  = [0x76,0x77,0x78];       // shr_u, rotl, rotr — no shl (loses bits)

function genStep(lcg) {
  const shiftOp  = SHIFT_OPS[lcg.range(0, SHIFT_OPS.length)];
  const shiftAmt = 8 + lcg.range(0, 8); // min 8 bits
  const binOp    = BINARY_OPS[lcg.range(0, BINARY_OPS.length)];
  const constVal = (lcg.next() | 1) | 0;
  return { shiftOp, shiftAmt, binOp, constVal };
}

// Run computation in pure JS (mirrors Wasm result)
function runSpec(regSeed, gameSeed) {
  const lcg = new LCG(regSeed);
  const numSteps = lcg.range(4, 7);
  const steps = Array.from({length: numSteps}, () => genStep(lcg));

  const applyShift = (val, op, n) => {
    n = n & 31;
    val = val >>> 0;
    switch(op) {
      case 0x74: return (val << n) >>> 0;          // shl
      case 0x76: return (val >>> n) >>> 0;          // shr_u
      case 0x77: return ((val << n) | (val >>> (32-n))) >>> 0; // rotl
      case 0x78: return ((val >>> n) | (val << (32-n))) >>> 0; // rotr
    }
  };

  const applyBin = (val, op, c) => {
    val = val >>> 0; c = c >>> 0;
    switch(op) {
      case 0x6a: return (val + c) >>> 0;
      case 0x6b: return (val - c) >>> 0;
      case 0x6c: return Math.imul(val, c) >>> 0;
      case 0x71: return (val & c) >>> 0;
      case 0x72: return (val | c) >>> 0;
      case 0x73: return (val ^ c) >>> 0;
    }
  };

  let val = gameSeed >>> 0;
  for (const s of steps) {
    val = applyShift(val, s.shiftOp, s.shiftAmt);
    val = applyBin(val, s.binOp, s.constVal);
  }
  return val >>> 0;
}

// ============================================================
// In-memory session store (production: Redis with TTL)
// ============================================================
const sessions = new Map();
const SESSION_TTL = 60_000; // 60 seconds

function cleanSessions() {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.created > SESSION_TTL) sessions.delete(id);
  }
}
setInterval(cleanSessions, 10_000);

// ============================================================
// API
// ============================================================

const UVS_SUPPORTED_VERSIONS = [1]; // integer versions; exclude broken ones explicitly

function negotiateVersion(clientVersions) {
  if (!Array.isArray(clientVersions)) return null;
  const intersection = clientVersions.filter(v => UVS_SUPPORTED_VERSIONS.includes(v));
  if (!intersection.length) return null;
  return Math.max(...intersection);
}

// POST /session/new
// Client requests a new session — Registrar issues a seed with UVS version negotiation
app.post('/session/new', (req, res) => {
  const { gameSeed, versions = [10] } = req.body;
  if (gameSeed === undefined) return res.status(400).json({ error: 'gameSeed required' });

  // UVS version negotiation (integer sets)
  const negotiated = negotiateVersion(versions);
  if (!negotiated) {
    return res.json({
      accepted: false,
      serverVersions: UVS_SUPPORTED_VERSIONS
    });
  }

  const sessionId  = crypto.randomBytes(8).toString('hex');
  const regSeed    = crypto.randomInt(0x100000, 0xFFFFFFFF);

  sessions.set(sessionId, {
    regSeed,
    gameSeed: gameSeed >>> 0,
    uvsVersion: negotiated,
    created: Date.now(),
    verified: false,
  });

  console.log(`[${sessionId}] New session | UVS ${negotiated} | regSeed=0x${regSeed.toString(16).toUpperCase()} | gameSeed=${gameSeed}`);

  res.json({
    accepted: true,
    negotiated,
    serverVersions: UVS_SUPPORTED_VERSIONS,
    sessionId,
    regSeed,
    expiresIn: SESSION_TTL / 1000,
  });
});

// POST /session/verify
// Client submits regSeed + gameSeed + result — Registrar verifies independently
app.post('/session/verify', (req, res) => {
  const { sessionId, regSeed, gameSeed, result } = req.body;

  if (!regSeed || gameSeed === undefined) {
    return res.status(400).json({ error: 'regSeed and gameSeed required' });
  }

  const serverResult = runSpec(regSeed >>> 0, gameSeed >>> 0);
  const ok = (result >>> 0) === serverResult;

  console.log(`[${sessionId}] Verify | client=0x${(result>>>0).toString(16).toUpperCase()} server=0x${serverResult.toString(16).toUpperCase()} → ${ok ? 'OK' : 'FAIL'}`);

  res.json({ ok, sessionId });
});

// GET /debug/:regSeed/:gameSeed — returns step-by-step trace
app.get('/debug/:regSeed/:gameSeed', (req, res) => {
  const regSeed  = parseInt(req.params.regSeed)  >>> 0;
  const gameSeed = parseInt(req.params.gameSeed) >>> 0;
  const lcg = new LCG(regSeed);
  const numSteps = lcg.range(4, 7);
  const steps = Array.from({length: numSteps}, () => genStep(lcg));
  const OP_NAMES = {0x6a:'add',0x6b:'sub',0x6c:'mul',0x73:'xor',0x76:'shr_u',0x77:'rotl',0x78:'rotr'};

  const applyShift = (val, op, n) => {
    n = n & 31; val = val >>> 0;
    switch(op) {
      case 0x76: return (val >>> n) >>> 0;
      case 0x77: return ((val << n) | (val >>> (32-n))) >>> 0;
      case 0x78: return ((val >>> n) | (val << (32-n))) >>> 0;
    }
  };
  const applyBin = (val, op, c) => {
    val = val >>> 0; c = c >>> 0;
    switch(op) {
      case 0x6a: return (val + c) >>> 0;
      case 0x6b: return (val - c) >>> 0;
      case 0x6c: return Math.imul(val, c) >>> 0;
      case 0x73: return (val ^ c) >>> 0;
    }
  };

  let val = gameSeed >>> 0;
  const trace = [];
  for (const s of steps) {
    const before = val;
    val = applyShift(val, s.shiftOp, s.shiftAmt);
    const afterShift = val;
    val = applyBin(val, s.binOp, s.constVal);
    trace.push({
      shiftOp: OP_NAMES[s.shiftOp], shiftAmt: s.shiftAmt,
      binOp: OP_NAMES[s.binOp], constVal: '0x'+(s.constVal>>>0).toString(16).toUpperCase(),
      before: '0x'+before.toString(16).toUpperCase(),
      afterShift: '0x'+afterShift.toString(16).toUpperCase(),
      after: '0x'+val.toString(16).toUpperCase(),
    });
  }
  res.json({ regSeed, gameSeed, numSteps, steps: trace, result: '0x'+val.toString(16).toUpperCase() });
});


const REGISTRAR_VERSION = '2.1.1';

app.get('/version', (req, res) => {
  res.json({ version: REGISTRAR_VERSION, uvsVersion: 1, engine: 'ChaCha20+SHA512' });
});

app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    version: REGISTRAR_VERSION,
    activeSessions: sessions.size,
    engines: ['paddla'],
    uptime: process.uptime().toFixed(1) + 's',
  });
});

// ============================================================
// PADDLA ENGINE — via npm paddla-engine (single source of truth)
// ============================================================
// createInitialState, engineTick, sha256Hex imported at top via require('paddla-engine')

// POST /verify/paddla — Full game verification with diagnostic event log
app.post('/verify/paddla', (req, res) => {
  const { regSeed, gameSeed, inputLog, eventLog, clientTotalWin, numBalls, betPerBall } = req.body;
  
  if (!regSeed || gameSeed === undefined || !inputLog || !numBalls) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  // Compute serverSeed from WASM result (UVS 1.0: padStart 64 to match client)
  const wasmResult = runSpec(regSeed >>> 0, gameSeed >>> 0);
  const serverSeed = wasmResult.toString(16).padStart(64, '0');
  
  // Replay game with event log tracking
  const state = createInitialState(serverSeed, numBalls, betPerBall || 5);
  let tickIdx = 0;
  let firstMismatch = null;
  const clientLogByTick = {};
  if (Array.isArray(eventLog)) {
    for (const entry of eventLog) clientLogByTick[entry.tick] = entry;
  }

  while (!state.finished && tickIdx < 200000) {
    const entry = inputLog[tickIdx];
    const target = entry?.target || null;
    engineTick(state, target);
    tickIdx++;

    // Diagnostic: compare stateHash on event ticks
    if (!firstMismatch && clientLogByTick[state.tickCount]) {
      const clientEntry = clientLogByTick[state.tickCount];
      const stateSnap = { totalWin: state.totalWin, progressive: state.progressive, ballsSpawned: state.ballsSpawned, ballsOnField: state.balls.length };
      const serverHash = sha256Hex(JSON.stringify(stateSnap));
      if (serverHash !== clientEntry.stateHash) {
        firstMismatch = {
          tick: state.tickCount,
          event: clientEntry.events?.[0] || 'unknown',
          clientHash: clientEntry.stateHash,
          serverHash
        };
      }
    }
  }
  
  const serverWin = state.totalWin;
  const clientWin = parseFloat(clientTotalWin) || 0;
  const ok = Math.abs(serverWin - clientWin) < 0.01;
  
  console.log(`[PADDLA] Verify | server=${serverWin} client=${clientWin} → ${ok ? 'MATCH' : 'MISMATCH'}${firstMismatch ? ` | first divergence tick ${firstMismatch.tick}` : ''}`);
  
  res.json({
    ok,
    serverTotalWin: serverWin,
    clientTotalWin: clientWin,
    ticks: state.tickCount,
    ballsProcessed: state.ballsSpawned,
    firstMismatch: firstMismatch || undefined
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Registrar server running on port ${PORT}`);
  console.log(`Endpoints: POST /session/new  POST /session/verify  GET /status`);
});
