/**
 * REGISTRAR SERVER v2.1.5 — Uncloned Math — UVS 1.0
 * 
 * Roles:
 *   1. Issues session seeds (regSeed → WASM → finalSeed)
 *   2. Verifies WASM computation
 *   3. Verifies PADDLA game results (full engine replay)
 */

const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const http    = require('http');
const { WebSocketServer } = require('ws');
const { NoisoreEngine } = require('./engine-server');
const { createInitialState, tick: engineTick, sha256Hex } = require('paddla-engine');

const app  = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

// Mobile detection — redirect to GitHub Pages mobile version
app.get('/', (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(ua);
  if (isMobile) {
    res.redirect('https://constarik.github.io/Paddla/mobile.html');
  } else {
    res.status(200).json({ status: 'Registrar API', version: REGISTRAR_VERSION });
  }
});

app.use(express.static(__dirname));

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
  const { gameSeed, versions = [1] } = req.body;
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


const REGISTRAR_VERSION = '2.1.5';

app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PADDLA Registrar v${REGISTRAR_VERSION}</title>
<style>
  body { margin:0; background:#0a0a1a; color:#fff; font-family:'Courier New',monospace;
    display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:100vh; gap:20px; }
  h1 { color:#00d4ff; font-size:1.4rem; letter-spacing:3px; text-shadow:0 0 20px rgba(0,212,255,0.8); }
  .badge { background:rgba(0,255,100,0.15); border:1px solid #00cc55; padding:6px 16px;
    border-radius:12px; font-size:11px; color:#00cc55; letter-spacing:1px; }
  .links { display:flex; gap:16px; flex-wrap:wrap; justify-content:center; }
  a { padding:12px 28px; border-radius:10px; text-decoration:none; font-weight:bold;
    font-size:14px; letter-spacing:1px; transition:transform 0.15s; }
  a:hover { transform:scale(1.05); }
  .desktop { background:linear-gradient(180deg,#00d4ff,#0099cc); color:#000; }
  .mobile  { background:linear-gradient(180deg,#00cc55,#007733); color:#000; }
  .status  { font-size:10px; color:#555; }
</style></head>
<body>
  <h1>🏓 PADDLA</h1>
  <div class="badge">🔒 UVS v1 | Registrar v${REGISTRAR_VERSION}</div>
  <div class="links">
    <a class="desktop" href="https://constarik.github.io/Paddla/">🖥 Desktop</a>
    <a class="mobile"  href="https://constarik.github.io/Paddla/mobile.html">📱 Mobile</a>
  </div>
  <div class="status">registrar.uncloned.work</div>
</body></html>`);
});

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
    play: {
      desktop: 'https://constarik.github.io/Paddla/',
      mobile:  'https://constarik.github.io/Paddla/mobile.html',
    },
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

// POST /simulate/paddla — server-side RTP simulation
const SIMULATE_MAX_GAMES = 500;
const SIMULATE_MAX_BALLS = 200;

app.post('/simulate/paddla', (req, res) => {
  const { strategy = 'stationary', numGames = 100, ballsPerGame = 100 } = req.body;

  // Validation
  if (numGames < 1 || numGames > SIMULATE_MAX_GAMES)
    return res.status(400).json({ error: `numGames must be 1–${SIMULATE_MAX_GAMES}` });
  if (ballsPerGame < 10 || ballsPerGame > SIMULATE_MAX_BALLS)
    return res.status(400).json({ error: `ballsPerGame must be 10–${SIMULATE_MAX_BALLS}` });

  const betPerBall = 5;
  const actualBet = ballsPerGame * betPerBall;
  const t0 = Date.now();
  let totalWin = 0;
  const rtps = [];

  for (let g = 0; g < numGames; g++) {
    const seed = Math.random().toString(16).slice(2).padEnd(64, '0');
    const state = createInitialState(seed, ballsPerGame, betPerBall);
    let ticks = 0;
    while (!state.finished && ticks < 200000) {
      engineTick(state, null);
      ticks++;
    }
    totalWin += state.totalWin;
    rtps.push(state.totalWin / actualBet * 100);
  }

  const avgRtp = totalWin / (numGames * actualBet) * 100;
  const stdDev = Math.sqrt(rtps.reduce((s, r) => s + (r - avgRtp) ** 2, 0) / rtps.length);
  const elapsed = ((Date.now() - t0) / 1000).toFixed(2);

  console.log(`[SIM] strategy=${strategy} games=${numGames} balls=${ballsPerGame} rtp=${avgRtp.toFixed(2)}% elapsed=${elapsed}s`);

  res.json({
    ok: true,
    strategy,
    numGames,
    ballsPerGame,
    avgRtp: parseFloat(avgRtp.toFixed(2)),
    stdDev: parseFloat(stdDev.toFixed(2)),
    min: parseFloat(Math.min(...rtps).toFixed(2)),
    max: parseFloat(Math.max(...rtps).toFixed(2)),
    elapsed: parseFloat(elapsed)
  });
});

// ============================================================
// NOISORE MULTIPLAYER — UVS v2 Move Sync G=1
// ============================================================

// ChaCha20 (RFC 8439) — same as uvs-sdk
function chacha20Block(key, nonce, counter) {
  const rotl = (v, n) => ((v << n) | (v >>> (32 - n))) >>> 0;
  const qr = (s, a, b, c, d) => {
    s[a]=(s[a]+s[b])>>>0;s[d]=rotl(s[d]^s[a],16);
    s[c]=(s[c]+s[d])>>>0;s[b]=rotl(s[b]^s[c],12);
    s[a]=(s[a]+s[b])>>>0;s[d]=rotl(s[d]^s[a],8);
    s[c]=(s[c]+s[d])>>>0;s[b]=rotl(s[b]^s[c],7);
  };
  const k = new Uint32Array(8), n2 = new Uint32Array(3);
  for (let i=0;i<8;i++) k[i]=key.readUInt32LE(i*4);
  for (let i=0;i<3;i++) n2[i]=nonce.readUInt32LE(i*4);
  const s = new Uint32Array([0x61707865,0x3320646e,0x79622d32,0x6b206574,k[0],k[1],k[2],k[3],k[4],k[5],k[6],k[7],counter>>>0,n2[0],n2[1],n2[2]]);
  const w = new Uint32Array(s);
  for(let i=0;i<10;i++){qr(w,0,4,8,12);qr(w,1,5,9,13);qr(w,2,6,10,14);qr(w,3,7,11,15);qr(w,0,5,10,15);qr(w,1,6,11,12);qr(w,2,7,8,13);qr(w,3,4,9,14);}
  const out = Buffer.alloc(64);
  for(let i=0;i<16;i++) out.writeUInt32LE((w[i]+s[i])>>>0,i*4);
  return out;
}
class ChaCha20 {
  constructor(key, nonce) { this._key=key;this._nonce=nonce;this._counter=0;this._buf=[];this._totalCalls=0; }
  nextUint32() { if(!this._buf.length){const b=chacha20Block(this._key,this._nonce,this._counter++);for(let i=0;i<64;i+=4)this._buf.push(b.readUInt32LE(i));}this._totalCalls++;return this._buf.shift(); }
  nextFloat() { return this.nextUint32()/0x100000000; }
  get calls() { return this._totalCalls; }
  static fromCombinedSeed(hex) { const buf=Buffer.from(hex,'hex');return new ChaCha20(buf.slice(0,32),buf.slice(32,44)); }
}
function sha256n(str) { return crypto.createHash('sha256').update(str).digest('hex'); }
function sha512n(str) { return crypto.createHash('sha512').update(str).digest('hex'); }

// Room Manager
const rooms = new Map();
let roomCounter = 1000;
class Room {
  constructor(id, config) {
    this.id=id; this.players=new Map(); this.config=config;
    this.state='LOBBY'; this.engine=null; this.uvs=null;
    this.tick=0; this.pendingMoves=new Map(); this.dropPower=0;
    this.moveTimeout=null; this.MOVE_WINDOW_MS=10000; this.hostId=null;
  }
  broadcast(msg) { const s=JSON.stringify(msg); for(const[,p]of this.players) if(p.ws.readyState===1) p.ws.send(s); }
  addPlayer(pid,name,color,ws) {
    if(this.state!=='LOBBY') return {error:'game_in_progress'};
    if(this.players.size>=(this.config.maxPlayers||6)) return {error:'room_full'};
    this.players.set(pid,{ws,name,color}); if(!this.hostId)this.hostId=pid;
    this.broadcastLobby(); return {ok:true};
  }
  removePlayer(pid) {
    this.players.delete(pid);
    if(pid===this.hostId){const n=this.players.keys().next();this.hostId=n.done?null:n.value;}
    if(!this.players.size){rooms.delete(this.id);return;}
    if(this.state==='LOBBY')this.broadcastLobby(); else this.broadcast({type:'player_left',playerId:pid});
  }
  broadcastLobby() {
    const pl=[];for(const[id,p]of this.players)pl.push({id,name:p.name,color:p.color,isHost:id===this.hostId});
    this.broadcast({type:'lobby',roomId:this.id,players:pl,config:this.config});
  }
  startGame() {
    if(this.players.size<2) return {error:'need_2_players'};
    const ss=crypto.randomBytes(32).toString('hex'), cs='noisore-room-'+this.id+'-'+Date.now(), nonce='1';
    const ssh=sha256n(ss), combined=sha512n(ss+':'+cs+':'+nonce);
    const rng=ChaCha20.fromCombinedSeed(combined);
    this.uvs={serverSeed:ss,clientSeed:cs,nonce,serverSeedHash:ssh,moves:[]};
    const gs=this.config.gridSize||6;
    this.engine=new NoisoreEngine(gs,gs,10,this.config.rotate,rng);
    this.engine.initGrid(); this.state='PLAYING'; this.tick=0;
    this.broadcast({type:'game_start',serverSeedHash:ssh,clientSeed:cs,nonce,grid:this.engine.copyGrid(),config:this.config});
    this.startTick(); return {ok:true};
  }
  startTick() {
    this.tick++; this.dropPower=this.engine.randDrop(); this.pendingMoves.clear();
    // Fisher-Yates shuffle via ChaCha20 — deterministic, verifiable
    const order=[...this.players.keys()];
    for(let i=order.length-1;i>0;i--){const j=this.engine.rng.nextUint32()%(i+1);[order[i],order[j]]=[order[j],order[i]];}
    this.tickOrder=order;
    this.broadcast({type:'tick_start',tick:this.tick,dropPower:this.dropPower,order});
    this.moveTimeout=setTimeout(()=>this.resolveTick(),this.MOVE_WINDOW_MS);
  }
  receiveMove(pid,col) {
    if(this.state!=='PLAYING'||this.pendingMoves.has(pid))return;
    if(col<0||col>=this.engine.COLS)return;
    this.pendingMoves.set(pid,col);
    this.broadcast({type:'move_locked',playerId:pid,tick:this.tick});
    if(this.pendingMoves.size===this.players.size){clearTimeout(this.moveTimeout);this.resolveTick();}
  }
  resolveTick() {
    const order=this.tickOrder||[...this.players.keys()];
    const results=[]; let winner=null;
    for(const pid of order){
      const col=this.pendingMoves.has(pid)?this.pendingMoves.get(pid):Math.floor(this.engine.gameRng()*this.engine.COLS);
      const rngPos=this.engine.rng.calls;
      const dr=this.engine.applyDrop(col,this.dropPower);
      this.uvs.moves.push({tick:this.tick,playerId:pid,col,dp:this.dropPower,rngPos,skip:!this.pendingMoves.has(pid)});
      results.push({playerId:pid,name:this.players.get(pid)?.name||pid,color:this.players.get(pid)?.color||'#888',col,dp:this.dropPower,path:dr.path,skip:!this.pendingMoves.has(pid)});
      if(this.engine.hasChannel()){winner=pid;break;}
    }
    let rotated=false;
    if(!winner&&this.config.rotate){
      const rp=this.engine.rng.calls;this.engine.rotateGridCW();this.engine.fillRowIfChannel();
      this.uvs.moves.push({type:'rotate',tick:this.tick,rngPos:rp});rotated=true;
    }
    this.broadcast({type:'tick_result',tick:this.tick,results,grid:this.engine.copyGrid(),rotated,
      winner:winner?{playerId:winner,name:this.players.get(winner)?.name||winner,channel:this.engine.findChannelCells()}:null});
    if(winner) this.endGame(winner); else this.startTick();
  }
  endGame(wid) {
    this.state='FINISHED';
    this.broadcast({type:'game_end',winner:{playerId:wid,name:this.players.get(wid)?.name||wid},
      uvs:{serverSeed:this.uvs.serverSeed,serverSeedHash:this.uvs.serverSeedHash,clientSeed:this.uvs.clientSeed,
        nonce:this.uvs.nonce,rngCalls:this.engine.rng.calls,moves:this.uvs.moves,
        verified:sha256n(this.uvs.serverSeed)===this.uvs.serverSeedHash}});
    setTimeout(()=>{if(rooms.has(this.id)&&this.state==='FINISHED')rooms.delete(this.id);},60000);
  }
}

// NOISORE HTTP endpoints
app.get('/noisore/rooms', (req, res) => {
  const list=[];for(const[id,r]of rooms){if(r.state==='LOBBY')list.push({id,players:r.players.size,config:r.config});}
  res.json(list);
});
app.get('/noisore/status', (req, res) => {
  res.json({status:'online',rooms:rooms.size,game:'NOISORE',protocol:'UVS v2 Move Sync G=1'});
});

// ============================================================
// HTTP + WebSocket Server
// ============================================================
const PORT = process.env.PORT || 3000;
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  let playerId='p-'+crypto.randomBytes(4).toString('hex'), currentRoom=null;
  ws.on('message', (raw) => {
    let msg; try{msg=JSON.parse(raw);}catch{return;}
    switch(msg.type){
      case 'create_room':{
        const cfg={gridSize:Math.min(Math.max(msg.gridSize||6,4),10),rotate:msg.rotate!==false,maxPlayers:Math.min(Math.max(msg.maxPlayers||4,2),6)};
        const rid=String(++roomCounter);const room=new Room(rid,cfg);rooms.set(rid,room);currentRoom=room;
        playerId=msg.name||playerId;room.addPlayer(playerId,msg.name||'Player',msg.color||'#f59e0b',ws);
        ws.send(JSON.stringify({type:'room_created',roomId:rid,playerId}));break;
      }
      case 'join_room':{
        const room=rooms.get(msg.roomId);
        if(!room){ws.send(JSON.stringify({type:'error',error:'room_not_found'}));break;}
        playerId=msg.name||playerId;
        const r=room.addPlayer(playerId,msg.name||'Player',msg.color||'#38bdf8',ws);
        if(r.error){ws.send(JSON.stringify({type:'error',error:r.error}));break;}
        currentRoom=room;ws.send(JSON.stringify({type:'room_joined',roomId:msg.roomId,playerId}));break;
      }
      case 'start_game':{
        if(!currentRoom||playerId!==currentRoom.hostId){ws.send(JSON.stringify({type:'error',error:'not_host'}));break;}
        const r=currentRoom.startGame();if(r.error)ws.send(JSON.stringify({type:'error',error:r.error}));break;
      }
      case 'move':{ if(currentRoom)currentRoom.receiveMove(playerId,msg.col);break; }
      case 'list_rooms':{
        const l=[];for(const[id,r]of rooms)if(r.state==='LOBBY')l.push({id,players:r.players.size,config:r.config});
        ws.send(JSON.stringify({type:'room_list',rooms:l}));break;
      }
    }
  });
  ws.on('close', () => { if(currentRoom)currentRoom.removePlayer(playerId); });
});

server.listen(PORT, () => {
  console.log(`Registrar server running on port ${PORT}`);
  console.log(`PADDLA: POST /session/new  POST /session/verify  GET /status`);
  console.log(`NOISORE: WebSocket + GET /noisore/rooms  GET /noisore/status`);
});
