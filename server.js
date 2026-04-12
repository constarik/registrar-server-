/**
 * REGISTRAR SERVER — Uncloned Math
 * 
 * Roles:
 *   1. Issues session seeds (regSeed → WASM → finalSeed)
 *   2. Verifies WASM computation
 *   3. Verifies PADDLA game results (full engine replay)
 */

const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');

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

// POST /session/new
// Client requests a new session — Registrar issues a seed
app.post('/session/new', (req, res) => {
  const { gameSeed } = req.body;
  if (gameSeed === undefined) return res.status(400).json({ error: 'gameSeed required' });

  const sessionId  = crypto.randomBytes(8).toString('hex');
  const regSeed    = crypto.randomInt(0x100000, 0xFFFFFFFF);

  sessions.set(sessionId, {
    regSeed,
    gameSeed: gameSeed >>> 0,
    created: Date.now(),
    verified: false,
  });

  console.log(`[${sessionId}] New session | regSeed=0x${regSeed.toString(16).toUpperCase()} | gameSeed=${gameSeed}`);

  res.json({
    sessionId,
    regSeed,             // client uses this to generate Wasm binary
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


app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    activeSessions: sessions.size,
    engines: ['paddla'],
    uptime: process.uptime().toFixed(1) + 's',
  });
});

// ============================================================
// PADDLA ENGINE — Full game verification
// ============================================================

// Deterministic math helpers
const FP_ROUND = 1e10;
function fpRound(v) { return Math.round(v * FP_ROUND) / FP_ROUND; }
function moneyRound(v) { return Math.round(v * 100) / 100; }
function dist(ax, ay, bx, by) { return Math.sqrt((bx-ax)**2 + (by-ay)**2); }
function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

// ===== UVS 1.0 PRNG (ChaCha20 + SHA-512, matches client Engine v9) =====
function sha512Hex(msg) {
  return crypto.createHash('sha512').update(msg).digest('hex');
}

class UVS_PRNG {
  constructor(combinedSeedHex) {
    const buf = Buffer.from(combinedSeedHex, 'hex');
    const key   = buf.slice(0, 32);
    const nonce = buf.slice(32, 44);
    const iv = Buffer.alloc(16);
    iv.writeUInt32LE(0, 0);
    nonce.copy(iv, 4);
    const zeros = Buffer.alloc(256);
    const cipher = crypto.createCipheriv('chacha20', key, iv);
    this._stream = cipher.update(zeros);
    this._pos = 0;
    this._log = [];
  }
  nextUint32() {
    const val = this._stream.readUInt32LE(this._pos);
    this._pos += 4;
    this._log.push(val);
    return val;
  }
  nextDouble() {
    const hi = this.nextUint32();
    const lo = this.nextUint32();
    return (hi * 0x100000000 + lo) / 0x10000000000000000;
  }
  consumed() { return [...this._log]; }
}

function tickCombinedSeed(serverSeed, bumperX, bumperY, tick) {
  return sha512Hex(`${serverSeed}:${bumperX.toFixed(4)}:${bumperY.toFixed(4)}:${tick}`);
}

// PADDLA Config (must match client exactly)
const PADDLA = {
  FIELD: 9, BALL_R: 0.2, SPEED: 0.05, GOAL_R: 1.02, CENTER_R: 0.225, CENTER_X: 4.5, CENTER_Y: 4.5,
  COUNTDOWN: 45, GOLDEN_CHANCE: 0.01, EXPLOSIVE_CHANCE: 1/75, SPAWN_COOLDOWN: 60, SPAWN_INTERVAL: 60,
  MAX_ON_FIELD: 10, TIMEOUT_LIMIT: 5, PROGRESSIVE_CAP: 5,
  BUMPER: { RADIUS: 0.4, MIN_Y: 0.4, MAX_Y: 3.5, MIN_X: 1.5, MAX_X: 7.5, MAX_SPEED: 0.15, START_X: 4.5, START_Y: 2.0 }
};

function isInLeftGoal(b) { return dist(b.x, b.y, 0, 0) < PADDLA.GOAL_R; }
function isInRightGoal(b) { return dist(b.x, b.y, PADDLA.FIELD, 0) < PADDLA.GOAL_R; }
function isGoal(b) { return isInLeftGoal(b) || isInRightGoal(b); }
function isInCenter(b) { return dist(b.x, b.y, PADDLA.CENTER_X, PADDLA.CENTER_Y) < PADDLA.CENTER_R + PADDLA.BALL_R; }
function isInUpperHalf(b) { return b.y < PADDLA.FIELD / 2; }

function createBumper() { return { x: PADDLA.BUMPER.START_X, y: PADDLA.BUMPER.START_Y, targetX: PADDLA.BUMPER.START_X, targetY: PADDLA.BUMPER.START_Y }; }

function moveBumper(bumper) {
  const dx = bumper.targetX - bumper.x, dy = bumper.targetY - bumper.y, d = Math.sqrt(dx*dx + dy*dy);
  if (d > PADDLA.BUMPER.MAX_SPEED) { bumper.x = fpRound(bumper.x + (dx/d) * PADDLA.BUMPER.MAX_SPEED); bumper.y = fpRound(bumper.y + (dy/d) * PADDLA.BUMPER.MAX_SPEED); }
  else { bumper.x = bumper.targetX; bumper.y = bumper.targetY; }
}

function createBall(rng, id) {
  const x = 0.5 + rng.nextDouble() * 8, y = PADDLA.FIELD - 0.3;
  const angle = (220 + rng.nextDouble() * 100) * Math.PI / 180;
  const typeRoll = rng.nextDouble();
  let type = 'normal', multiplier = 1;
  if (typeRoll < PADDLA.GOLDEN_CHANCE) { type = 'golden'; multiplier = 3; }
  else if (typeRoll < PADDLA.GOLDEN_CHANCE + PADDLA.EXPLOSIVE_CHANCE) { type = 'explosive'; }
  return { id, x, y, dx: Math.cos(angle) * PADDLA.SPEED, dy: Math.sin(angle) * PADDLA.SPEED, value: 9, ticksSinceCountdown: 0, alive: true, type, multiplier };
}

function randomizeBounce(ball, rng) {
  const variation = (rng.nextDouble() - 0.5) * 0.1 * Math.PI;
  const angle = Math.atan2(ball.dy, ball.dx) + variation;
  const speed = Math.sqrt(ball.dx**2 + ball.dy**2);
  ball.dx = fpRound(Math.cos(angle) * speed);
  ball.dy = fpRound(Math.sin(angle) * speed);
}

function collideBallBumper(ball, bumper, rng) {
  const d = dist(ball.x, ball.y, bumper.x, bumper.y), minDist = PADDLA.BALL_R + PADDLA.BUMPER.RADIUS;
  if (d < minDist && d > 0) {
    const nx = (ball.x - bumper.x)/d, ny = (ball.y - bumper.y)/d, dot = ball.dx*nx + ball.dy*ny;
    ball.dx = fpRound(ball.dx - 2*dot*nx); ball.dy = fpRound(ball.dy - 2*dot*ny);
    ball.x = fpRound(bumper.x + nx*minDist); ball.y = fpRound(bumper.y + ny*minDist);
    randomizeBounce(ball, rng);
    return true;
  }
  return false;
}

function createPaddlaState(serverSeed, numBalls, betPerBall) {
  return { serverSeed, rng: null, balls: [], bumper: createBumper(), tickCount: 0, ballsSpawned: 0, numBalls, betPerBall, spawnCooldown: 0, progressive: 1, timeoutCount: 0, totalWin: 0, finished: false, nextBallId: 1 };
}

function paddlaTick(state, bumperTarget) {
  if (state.finished) return;
  state.tickCount++;
  if (state.spawnCooldown > 0) state.spawnCooldown--;
  
  if (bumperTarget) {
    state.bumper.targetX = clamp(bumperTarget.x, PADDLA.BUMPER.MIN_X, PADDLA.BUMPER.MAX_X);
    state.bumper.targetY = clamp(bumperTarget.y, PADDLA.BUMPER.MIN_Y, PADDLA.BUMPER.MAX_Y);
  }
  moveBumper(state.bumper);
  state.rng = new UVS_PRNG(tickCombinedSeed(state.serverSeed, state.bumper.x, state.bumper.y, state.tickCount));
  
  // Spawn
  if (state.tickCount % PADDLA.SPAWN_INTERVAL === 0 && state.balls.length < PADDLA.MAX_ON_FIELD && state.spawnCooldown <= 0 && state.ballsSpawned < state.numBalls) {
    state.balls.push(createBall(state.rng, state.nextBallId++));
    state.ballsSpawned++;
    state.spawnCooldown = PADDLA.SPAWN_COOLDOWN;
  }
  
  // Update balls
  for (const b of state.balls) {
    if (!b.alive) continue;
    b.ticksSinceCountdown++;
    b.x = fpRound(b.x + b.dx); b.y = fpRound(b.y + b.dy);
    const R = PADDLA.BALL_R, F = PADDLA.FIELD;
    if (b.x - R < 0) { b.x = R; b.dx = -b.dx; randomizeBounce(b, state.rng); }
    if (b.x + R > F) { b.x = F - R; b.dx = -b.dx; randomizeBounce(b, state.rng); }
    if (b.y - R < 0) { b.y = R; b.dy = -b.dy; randomizeBounce(b, state.rng); }
    if (b.y + R > F) { b.y = F - R; b.dy = -b.dy; randomizeBounce(b, state.rng); }
    if (b.type === 'normal' && b.ticksSinceCountdown >= PADDLA.COUNTDOWN && b.value > 0) {
      b.value--; b.ticksSinceCountdown = 0;
      if (b.value <= 0) { b.alive = false; b.diedFromTimeout = true; }
    }
  }
  
  // Bumper collision
  for (const b of state.balls) if (b.alive) collideBallBumper(b, state.bumper, state.rng);
  
  // Center recharge
  for (const b of state.balls) {
    if (b.alive && isInCenter(b)) {
      const dx = b.x - PADDLA.CENTER_X, dy = b.y - PADDLA.CENTER_Y, d = Math.sqrt(dx*dx+dy*dy);
      if (d > 0) { b.dx = (dx/d)*PADDLA.SPEED; b.dy = (dy/d)*PADDLA.SPEED; randomizeBounce(b, state.rng); }
      if (b.type === 'normal' && b.value < 9) { b.value = 9; b.ticksSinceCountdown = 0; }
    }
  }
  
  // Goals
  const betScale = state.betPerBall / 5;
  for (const ball of state.balls) {
    if (!ball.alive) continue;
    if (isGoal(ball)) {
      const prize = moneyRound(ball.value * ball.multiplier * state.progressive * betScale);
      state.totalWin = moneyRound(state.totalWin + prize);
      if (ball.type === 'golden') state.timeoutCount = 0;
      if (state.progressive < PADDLA.PROGRESSIVE_CAP) state.progressive++;
      ball.alive = false;
      if (ball.type === 'explosive') {
        state.timeoutCount = 0;
        for (const o of state.balls) {
          if (o.alive && o.id !== ball.id && isInUpperHalf(o)) {
            const ep = moneyRound(o.value * o.multiplier * state.progressive * betScale);
            state.totalWin = moneyRound(state.totalWin + ep);
            if (state.progressive < PADDLA.PROGRESSIVE_CAP) state.progressive++;
            o.alive = false;
          }
        }
      }
    }
  }
  
  // Ball-ball collisions
  for (let i = 0; i < state.balls.length; i++) {
    for (let j = i + 1; j < state.balls.length; j++) {
      const b1 = state.balls[i], b2 = state.balls[j];
      if (!b1.alive || !b2.alive) continue;
      if (dist(b1.x, b1.y, b2.x, b2.y) < PADDLA.BALL_R * 2) {
        const s1 = b1.type !== 'normal', s2 = b2.type !== 'normal';
        if (s1 && s2) {
          const dx = b2.x - b1.x, dy = b2.y - b1.y, d = Math.sqrt(dx*dx+dy*dy)||1, nx = dx/d, ny = dy/d, ov = PADDLA.BALL_R*2-d;
          if (ov > 0) { b1.x -= nx*ov*0.5; b1.y -= ny*ov*0.5; b2.x += nx*ov*0.5; b2.y += ny*ov*0.5; }
          b1.dx = -nx*PADDLA.SPEED; b1.dy = -ny*PADDLA.SPEED; b2.dx = nx*PADDLA.SPEED; b2.dy = ny*PADDLA.SPEED;
          randomizeBounce(b1, state.rng); randomizeBounce(b2, state.rng);
          continue;
        }
        if (s1) { b2.alive = false; state.totalWin = moneyRound(state.totalWin + betScale); continue; }
        if (s2) { b1.alive = false; state.totalWin = moneyRound(state.totalWin + betScale); continue; }
        if (b1.value === b2.value) {
          const prize = moneyRound(b1.value * 2 * betScale);
          state.totalWin = moneyRound(state.totalWin + prize);
          const roll = state.rng.nextDouble();
          if (roll < 0.5) b2.alive = false; else b1.alive = false;
        } else {
          state.totalWin = moneyRound(state.totalWin + betScale);
          const loser = b1.value < b2.value ? b1 : b2, winner = b1.value < b2.value ? b2 : b1;
          loser.alive = false;
          const dx = winner.x - loser.x, dy = winner.y - loser.y, d = Math.sqrt(dx*dx+dy*dy)||1;
          winner.dx = (dx/d)*PADDLA.SPEED; winner.dy = (dy/d)*PADDLA.SPEED;
          randomizeBounce(winner, state.rng);
        }
      }
    }
  }
  
  // Timeouts
  for (const b of state.balls) {
    if (!b.alive && b.diedFromTimeout) {
      state.timeoutCount++;
      if (state.timeoutCount >= PADDLA.TIMEOUT_LIMIT) { state.progressive = 1; state.timeoutCount = 0; }
      b.diedFromTimeout = false;
    }
  }
  state.balls = state.balls.filter(b => b.alive);
  
  // Auto-collect
  if (state.balls.length > 0 && !state.balls.some(b => b.type === 'normal')) {
    for (const b of state.balls) {
      if (b.alive) {
        const prize = moneyRound(b.value * b.multiplier * state.progressive * betScale);
        state.totalWin = moneyRound(state.totalWin + prize);
        if (state.progressive < PADDLA.PROGRESSIVE_CAP) state.progressive++;
        b.alive = false;
      }
    }
    state.balls = [];
  }
  
  // End
  if (state.ballsSpawned >= state.numBalls && state.balls.length === 0) state.finished = true;
}

// POST /verify/paddla — Full game verification
app.post('/verify/paddla', (req, res) => {
  const { regSeed, gameSeed, inputLog, clientTotalWin, numBalls, betPerBall } = req.body;
  
  if (!regSeed || gameSeed === undefined || !inputLog || !numBalls) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  // Compute serverSeed from WASM result (UVS 1.0: padStart 64 to match client)
  const wasmResult = runSpec(regSeed >>> 0, gameSeed >>> 0);
  const serverSeed = wasmResult.toString(16).padStart(64, '0');
  
  // Replay game
  const state = createPaddlaState(serverSeed, numBalls, betPerBall || 5);
  let tickIdx = 0;
  
  while (!state.finished && tickIdx < 200000) {
    const entry = inputLog[tickIdx];
    const target = entry?.target || null;
    paddlaTick(state, target);
    tickIdx++;
  }
  
  const serverWin = state.totalWin;
  const clientWin = parseFloat(clientTotalWin) || 0;
  const ok = Math.abs(serverWin - clientWin) < 0.01;
  
  console.log(`[PADDLA] Verify | server=${serverWin} client=${clientWin} → ${ok ? 'MATCH' : 'MISMATCH'}`);
  
  res.json({
    ok,
    serverTotalWin: serverWin,
    clientTotalWin: clientWin,
    ticks: state.tickCount,
    ballsProcessed: state.ballsSpawned
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Registrar server running on port ${PORT}`);
  console.log(`Endpoints: POST /session/new  POST /session/verify  GET /status`);
});
