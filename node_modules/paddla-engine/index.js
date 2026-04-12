// PADDLA Engine v9 - UVS 1.0 Compatible
// Provably fair via UVS protocol: github.com/constarik/uvs
// combinedSeed = SHA-512(serverSeed + ":" + clientSeed + ":" + nonce)
// PRNG: ChaCha20 (RFC 8439), key=combinedSeed[0..31], nonce=combinedSeed[32..43]

const ENGINE_VERSION = 9;

const _crypto = typeof window === 'undefined' ? require('crypto') : null;

// ===== SHA-256 pure JS (browser fallback) =====

const _SHA256_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

function _sha256Bytes(msg) {
  const bytes = typeof msg === 'string' ? new TextEncoder().encode(msg) : new Uint8Array(msg);
  const bitLen = bytes.length * 8;
  const padLen = (bytes.length + 9 + 63) & ~63;
  const padded = new Uint8Array(padLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padLen - 4, bitLen, false);
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
  let h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const w = new Uint32Array(64);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i*4, false);
    for (let i = 16; i < 64; i++) {
      const s0=((w[i-15]>>>7)|(w[i-15]<<25))^((w[i-15]>>>18)|(w[i-15]<<14))^(w[i-15]>>>3);
      const s1=((w[i-2]>>>17)|(w[i-2]<<15))^((w[i-2]>>>19)|(w[i-2]<<13))^(w[i-2]>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 64; i++) {
      const S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
      const ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+_SHA256_K[i]+w[i])>>>0;
      const S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
      const maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;
    h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
  }
  const r = new Uint8Array(32);
  const rv = new DataView(r.buffer);
  rv.setUint32(0,h0,false);rv.setUint32(4,h1,false);rv.setUint32(8,h2,false);rv.setUint32(12,h3,false);
  rv.setUint32(16,h4,false);rv.setUint32(20,h5,false);rv.setUint32(24,h6,false);rv.setUint32(28,h7,false);
  return r;
}

// ===== SHA-512 pure JS (browser fallback) =====

const _SHA512_K = [
  0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n,0x59f111f1b605d019n,0x923f82a4af194f9bn,0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n,0x12835b0145706fben,0x243185be4ee4b28cn,0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn,0x80deb1fe3b1696b1n,0x9bdc06a725c71235n,0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n,0xefbe4786384f25e3n,0x0fc19dc68b8cd5b5n,0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n,0x4a7484aa6ea6e483n,0x5cb0a9dcbd41fbd4n,0x76f988da831153b5n,
  0x983e5152ee66dfabn,0xa831c66d2db43210n,0xb00327c898fb213fn,0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n,0xd5a79147930aa725n,0x06ca6351e003826fn,0x142929670a0e6e70n,
  0x27b70a8546d22ffcn,0x2e1b21385c26c926n,0x4d2c6dfc5ac42aedn,0x53380d139d95b3dfn,
  0x650a73548baf63den,0x766a0abb3c77b2a8n,0x81c2c92e47edaee6n,0x92722c851482353bn,
  0xa2bfe8a14cf10364n,0xa81a664bbc423001n,0xc24b8b70d0f89791n,0xc76c51a30654be30n,
  0xd192e819d6ef5218n,0xd69906245565a910n,0xf40e35855771202an,0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n,0x1e376c085141ab53n,0x2748774cdf8eeb99n,0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n,0x4ed8aa4ae3418acbn,0x5b9cca4f7763e373n,0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn,0x78a5636f43172f60n,0x84c87814a1f0ab72n,0x8cc702081a6439ecn,
  0x90befffa23631e28n,0xa4506cebde82bde9n,0xbef9a3f7b2c67915n,0xc67178f2e372532bn,
  0xca273eceea26619cn,0xd186b8c721c0c207n,0xeada7dd6cde0eb1en,0xf57d4f7fee6ed178n,
  0x06f067aa72176fban,0x0a637dc5a2c898a6n,0x113f9804bef90daen,0x1b710b35131c471bn,
  0x28db77f523047d84n,0x32caab7b40c72493n,0x3c9ebe0a15c9bebcn,0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n,0x597f299cfc657e2an,0x5fcb6fab3ad6faecn,0x6c44198c4a475817n
];

function _sha512Bytes(msg) {
  const bytes = typeof msg === 'string' ? new TextEncoder().encode(msg) : new Uint8Array(msg);
  const bitLen = BigInt(bytes.length * 8);
  const padLen = (bytes.length + 17 + 127) & ~127;
  const padded = new Uint8Array(padLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setBigUint64(padLen - 8, bitLen, false);
  const M = 0xFFFFFFFFFFFFFFFFn;
  let h0=0x6a09e667f3bcc908n,h1=0xbb67ae8584caa73bn,h2=0x3c6ef372fe94f82bn,h3=0xa54ff53a5f1d36f1n;
  let h4=0x510e527fade682d1n,h5=0x9b05688c2b3e6c1fn,h6=0x1f83d9abfb41bd6bn,h7=0x5be0cd19137e2179n;
  const w = new Array(80);
  for (let off = 0; off < padLen; off += 128) {
    for (let i = 0; i < 16; i++) w[i] = dv.getBigUint64(off + i*8, false);
    for (let i = 16; i < 80; i++) {
      const w15=w[i-15], w2=w[i-2];
      const s0=((w15>>1n)|(w15<<63n))^((w15>>8n)|(w15<<56n))^(w15>>7n);
      const s1=((w2>>19n)|(w2<<45n))^((w2>>61n)|(w2<<3n))^(w2>>6n);
      w[i]=(w[i-16]+s0+w[i-7]+s1)&M;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 80; i++) {
      const S1=((e>>14n)|(e<<50n))^((e>>18n)|(e<<46n))^((e>>41n)|(e<<23n));
      const ch=(e&f)^(~e&g)&M;
      const t1=(h+S1+ch+_SHA512_K[i]+w[i])&M;
      const S0=((a>>28n)|(a<<36n))^((a>>34n)|(a<<30n))^((a>>39n)|(a<<25n));
      const maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)&M;
      h=g;g=f;f=e;e=(d+t1)&M;d=c;c=b;b=a;a=(t1+t2)&M;
    }
    h0=(h0+a)&M;h1=(h1+b)&M;h2=(h2+c)&M;h3=(h3+d)&M;
    h4=(h4+e)&M;h5=(h5+f)&M;h6=(h6+g)&M;h7=(h7+h)&M;
  }
  const r = new Uint8Array(64);
  const rv = new DataView(r.buffer);
  rv.setBigUint64(0,h0,false);rv.setBigUint64(8,h1,false);rv.setBigUint64(16,h2,false);rv.setBigUint64(24,h3,false);
  rv.setBigUint64(32,h4,false);rv.setBigUint64(40,h5,false);rv.setBigUint64(48,h6,false);rv.setBigUint64(56,h7,false);
  return r;
}

// ===== ChaCha20 pure JS (RFC 8439, browser fallback) =====

function _chacha20Block(key, nonce12, counter, out, outOff) {
  // key: Uint8Array[32], nonce12: Uint8Array[12], counter: number
  const s = new Uint32Array(16);
  const dv = new DataView(key.buffer, key.byteOffset);
  const nv = new DataView(nonce12.buffer, nonce12.byteOffset);
  s[0]=0x61707865;s[1]=0x3320646e;s[2]=0x79622d32;s[3]=0x6b206574;
  for (let i=0;i<8;i++) s[4+i]=dv.getUint32(i*4,true);
  s[12]=counter>>>0;
  s[13]=nv.getUint32(0,true);s[14]=nv.getUint32(4,true);s[15]=nv.getUint32(8,true);
  const x = s.slice();
  function qr(a,b,c,d){
    x[a]=(x[a]+x[b])>>>0;x[d]=Math.imul(x[d]^x[a],1)<<16|(x[d]^x[a])>>>16;
    x[c]=(x[c]+x[d])>>>0;x[b]=Math.imul(x[b]^x[c],1)<<12|(x[b]^x[c])>>>20;
    x[a]=(x[a]+x[b])>>>0;x[d]=Math.imul(x[d]^x[a],1)<<8|(x[d]^x[a])>>>24;
    x[c]=(x[c]+x[d])>>>0;x[b]=Math.imul(x[b]^x[c],1)<<7|(x[b]^x[c])>>>25;
  }
  for (let i=0;i<10;i++){
    qr(0,4,8,12);qr(1,5,9,13);qr(2,6,10,14);qr(3,7,11,15);
    qr(0,5,10,15);qr(1,6,11,12);qr(2,7,8,13);qr(3,4,9,14);
  }
  const ov = new DataView(out.buffer, out.byteOffset + outOff);
  for (let i=0;i<16;i++) ov.setUint32(i*4,((x[i]+s[i])>>>0),true);
}

function _chacha20KeystreamPure(key32, nonce12, numBytes) {
  const out = new Uint8Array(numBytes);
  const blocks = Math.ceil(numBytes / 64);
  const tmp = new Uint8Array(64);
  for (let b=0;b<blocks;b++){
    _chacha20Block(key32, nonce12, b, tmp, 0);
    const end = Math.min(64, numBytes - b*64);
    out.set(tmp.subarray(0, end), b*64);
  }
  return out;
}

// ===== Crypto helpers =====

function _bytesToHex(b) {
  return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
}

function sha256Hex(msg) {
  if (_crypto) {
    const data = typeof msg === 'string' ? msg : Buffer.from(msg);
    return _crypto.createHash('sha256').update(data).digest('hex');
  }
  return _bytesToHex(_sha256Bytes(msg));
}

function sha512Hex(msg) {
  if (_crypto) {
    const data = typeof msg === 'string' ? msg : Buffer.from(msg);
    return _crypto.createHash('sha512').update(data).digest('hex');
  }
  return _bytesToHex(_sha512Bytes(msg));
}

function _chacha20Keystream(key32buf, nonce12buf, numBytes) {
  if (_crypto) {
    const iv = Buffer.alloc(16);
    iv.writeUInt32LE(0, 0);
    nonce12buf.copy ? nonce12buf.copy(iv, 4) : iv.set(nonce12buf, 4);
    const zeros = Buffer.alloc(numBytes);
    const cipher = _crypto.createCipheriv('chacha20', key32buf, iv);
    return cipher.update(zeros);
  }
  return _chacha20KeystreamPure(key32buf, nonce12buf, numBytes);
}

// ===== UVS_PRNG (UVS 1.0 compliant) =====

class UVS_PRNG {
  constructor(combinedSeedHex) {
    // combinedSeed = SHA-512(serverSeed + ":" + clientSeed + ":" + nonce)
    // key   = bytes 0-31, nonce12 = bytes 32-43
    const buf = _crypto
      ? Buffer.from(combinedSeedHex, 'hex')
      : (()=>{ const b=new Uint8Array(64); for(let i=0;i<64;i++) b[i]=parseInt(combinedSeedHex.slice(i*2,i*2+2),16); return b; })();
    const key32   = _crypto ? buf.slice(0,32)  : buf.slice(0,32);
    const nonce12 = _crypto ? buf.slice(32,44) : buf.slice(32,44);
    // Pre-generate 256 bytes (64 uint32) — enough for any single tick
    this._stream = _chacha20Keystream(key32, nonce12, 256);
    this._pos = 0;
    this._log = [];
  }

  nextUint32() {
    if (this._pos + 4 > this._stream.length) {
      throw new Error('UVS_PRNG: keystream exhausted — increase pre-generated size');
    }
    const val = _crypto
      ? this._stream.readUInt32LE(this._pos)
      : new DataView(this._stream.buffer).getUint32(this._pos, true);
    this._pos += 4;
    this._log.push(val);
    return val;
  }

  nextDouble() {
    // Two uint32 → double [0, 1) with 53-bit precision
    const hi = this.nextUint32();
    const lo = this.nextUint32();
    return (hi * 0x100000000 + lo) / 0x10000000000000000;
  }

  consumed() {
    return [...this._log];
  }
}

// Per-tick combinedSeed: serverSeed is game secret, clientSeed encodes bumper position, nonce = tick
function _tickCombinedSeed(serverSeed, bumperX, bumperY, tick) {
  const clientSeed = `${bumperX.toFixed(4)}:${bumperY.toFixed(4)}`;
  return sha512Hex(`${serverSeed}:${clientSeed}:${tick}`);
}

// ===== UTILITIES =====

const FP_ROUND = 1e10;
function fpRound(v) { return Math.round(v * FP_ROUND) / FP_ROUND; }
function moneyRound(v) { return Math.round(v * 100) / 100; }
function dist(ax,ay,bx,by) { return Math.sqrt((bx-ax)**2+(by-ay)**2); }
function clamp(v,min,max) { return Math.max(min,Math.min(max,v)); }
function bytesToHex(b) { return _bytesToHex(b); }

// ===== CONFIG =====

const CONFIG = {
  FIELD:9, BALL_R:0.2, SPEED:0.05, GOAL_R:1.02,
  CENTER_R:0.225, CENTER_X:4.5, CENTER_Y:4.5, COUNTDOWN:45,
  GOLDEN_CHANCE:0.01, EXPLOSIVE_CHANCE:1/75,
  SPAWN_COOLDOWN:60, SPAWN_INTERVAL:60, MAX_ON_FIELD:10,
  TIMEOUT_LIMIT:5, PROGRESSIVE_CAP:5, BET_PER_BALL:5, MAX_TICKS_PER_BALL:600
};

const BUMPER = {
  RADIUS:0.4, MIN_Y:0.4, MAX_Y:3.5, MIN_X:1.5, MAX_X:7.5,
  MAX_SPEED:0.15, START_X:4.5, START_Y:2.0
};

// ===== HELPERS =====

function isInLeftGoal(b)  { return dist(b.x,b.y,0,0) < CONFIG.GOAL_R; }
function isInRightGoal(b) { return dist(b.x,b.y,CONFIG.FIELD,0) < CONFIG.GOAL_R; }
function isGoal(b)        { return isInLeftGoal(b) || isInRightGoal(b); }
function isInCenter(b)    { return dist(b.x,b.y,CONFIG.CENTER_X,CONFIG.CENTER_Y) < CONFIG.CENTER_R+CONFIG.BALL_R; }
function isInUpperHalf(b) { return b.y < CONFIG.FIELD/2; }

function createBumper() {
  return { x:BUMPER.START_X, y:BUMPER.START_Y, targetX:BUMPER.START_X, targetY:BUMPER.START_Y };
}

function moveBumper(bumper) {
  const dx=bumper.targetX-bumper.x, dy=bumper.targetY-bumper.y;
  const d=Math.sqrt(dx*dx+dy*dy);
  if (d > BUMPER.MAX_SPEED) {
    bumper.x=fpRound(bumper.x+(dx/d)*BUMPER.MAX_SPEED);
    bumper.y=fpRound(bumper.y+(dy/d)*BUMPER.MAX_SPEED);
  } else { bumper.x=bumper.targetX; bumper.y=bumper.targetY; }
}

// ===== BALL CREATION =====

function createBall(rng, id) {
  const x = 0.5 + rng.nextDouble() * 8;
  const y = CONFIG.FIELD - 0.3;
  const angle = (220 + rng.nextDouble() * 100) * Math.PI / 180;
  const typeRoll = rng.nextDouble();
  let type='normal', multiplier=1;
  if (typeRoll < CONFIG.GOLDEN_CHANCE) { type='golden'; multiplier=3; }
  else if (typeRoll < CONFIG.GOLDEN_CHANCE+CONFIG.EXPLOSIVE_CHANCE) { type='explosive'; }
  return {
    id, x, y,
    dx: Math.cos(angle)*CONFIG.SPEED,
    dy: Math.sin(angle)*CONFIG.SPEED,
    value:9, ticksSinceCountdown:0, alive:true, type, multiplier
  };
}

function randomizeBounce(ball, rng) {
  const variation = (rng.nextDouble() - 0.5) * 0.1 * Math.PI;
  const angle = Math.atan2(ball.dy, ball.dx) + variation;
  const speed = Math.sqrt(ball.dx**2 + ball.dy**2);
  ball.dx = fpRound(Math.cos(angle) * speed);
  ball.dy = fpRound(Math.sin(angle) * speed);
}

function collideBallBumper(ball, bumper, rng) {
  const d = dist(ball.x,ball.y,bumper.x,bumper.y);
  const minDist = CONFIG.BALL_R+BUMPER.RADIUS;
  if (d < minDist && d > 0) {
    const nx=(ball.x-bumper.x)/d, ny=(ball.y-bumper.y)/d;
    const dot=ball.dx*nx+ball.dy*ny;
    ball.dx=fpRound(ball.dx-2*dot*nx); ball.dy=fpRound(ball.dy-2*dot*ny);
    ball.x=fpRound(bumper.x+nx*minDist); ball.y=fpRound(bumper.y+ny*minDist);
    randomizeBounce(ball, rng);
    return true;
  }
  return false;
}

// ===== GAME STATE =====

function createInitialState(serverSeed, numBalls, betPerBall=5) {
  const serverSeedHash = sha256Hex(serverSeed);
  const sessionId = sha256Hex(`${serverSeedHash}:uvs-paddla:1`);
  return {
    // UVS session header
    uvsHeader: {
      type: 'uvs-header',
      uvsVersion: 1,
      sessionId,
      serverSeedHash,
      clientSeed: 'uvs-paddla',  // bumper position encoded per-tick in combinedSeed
      minNonce: 1,
      params: { numBalls, betPerBall },
      extensions: ['physics-arcade@1.0'],
      timestamp: new Date().toISOString()
    },
    // Game state
    serverSeed,
    rng: null,           // initialized per-tick in tick()
    balls: [],
    bumper: createBumper(),
    tickCount: 0,
    ballsSpawned: 0,
    numBalls,
    betPerBall,
    spawnCooldown: 0,
    progressive: 1,
    timeoutCount: 0,
    totalWin: 0,
    finished: false,
    nextBallId: 1,
    inputLog: []
  };
}

// ===== TICK =====

function tick(state, bumperTarget) {
  if (state.finished) return [];
  const events = [];

  state.tickCount++;
  if (state.spawnCooldown > 0) state.spawnCooldown--;

  // Apply bumper input first
  if (bumperTarget) {
    state.bumper.targetX = clamp(bumperTarget.x, BUMPER.MIN_X, BUMPER.MAX_X);
    state.bumper.targetY = clamp(bumperTarget.y, BUMPER.MIN_Y, BUMPER.MAX_Y);
  }
  moveBumper(state.bumper);

  // UVS: fresh PRNG per tick, combinedSeed encodes tick + bumper position
  const combinedSeed = _tickCombinedSeed(
    state.serverSeed, state.bumper.x, state.bumper.y, state.tickCount
  );
  state.rng = new UVS_PRNG(combinedSeed);

  // Log input for replay
  state.inputLog.push({
    tick: state.tickCount,
    target: { x: state.bumper.targetX, y: state.bumper.targetY }
  });

  // Spawn
  if (state.tickCount % CONFIG.SPAWN_INTERVAL === 0 &&
      state.balls.length < CONFIG.MAX_ON_FIELD &&
      state.spawnCooldown <= 0 &&
      state.ballsSpawned < state.numBalls) {
    const ball = createBall(state.rng, state.nextBallId++);
    state.balls.push(ball);
    state.ballsSpawned++;
    state.spawnCooldown = CONFIG.SPAWN_COOLDOWN;
    events.push({ type:'spawn', ball });
  }

  // Update balls
  for (const b of state.balls) {
    if (!b.alive) continue;
    b.ticksSinceCountdown++;
    b.x=fpRound(b.x+b.dx); b.y=fpRound(b.y+b.dy);
    const R=CONFIG.BALL_R, F=CONFIG.FIELD;
    let hitWall=false;
    if (b.x-R<0) { b.x=R; b.dx=-b.dx; hitWall=true; }
    if (b.x+R>F) { b.x=F-R; b.dx=-b.dx; hitWall=true; }
    if (b.y-R<0) { b.y=R; b.dy=-b.dy; hitWall=true; }
    if (b.y+R>F) { b.y=F-R; b.dy=-b.dy; hitWall=true; }
    if (b.type==='normal' && b.ticksSinceCountdown>=CONFIG.COUNTDOWN && b.value>0) {
      b.value--; b.ticksSinceCountdown=0;
      if (b.value<=0) { b.alive=false; b.diedFromTimeout=true; events.push({type:'timeout',ball:b}); }
    }
    if (b.alive && hitWall) randomizeBounce(b, state.rng);
  }

  // Bumper collision
  for (const b of state.balls) {
    if (b.alive && collideBallBumper(b, state.bumper, state.rng))
      events.push({ type:'bumperHit', ball:b });
  }

  // Center recharge
  for (const b of state.balls) {
    if (b.alive && isInCenter(b)) {
      const dx=b.x-CONFIG.CENTER_X, dy=b.y-CONFIG.CENTER_Y;
      const d=Math.sqrt(dx*dx+dy*dy);
      if (d>0) { b.dx=(dx/d)*CONFIG.SPEED; b.dy=(dy/d)*CONFIG.SPEED; randomizeBounce(b,state.rng); }
      if (b.type==='normal' && b.value<9) {
        b.value=9; b.ticksSinceCountdown=0;
        events.push({ type:'recharge', ball:b });
      }
    }
  }

  // Goals
  for (const ball of state.balls) {
    if (!ball.alive) continue;
    if (isGoal(ball)) {
      const bs=state.betPerBall/5;
      const prize=moneyRound(ball.value*ball.multiplier*state.progressive*bs);
      state.totalWin=moneyRound(state.totalWin+prize);
      if (ball.type==='golden') state.timeoutCount=0;
      if (state.progressive<CONFIG.PROGRESSIVE_CAP) state.progressive++;
      events.push({ type:'goal', ball, prize, side:isInLeftGoal(ball)?'left':'right' });
      ball.alive=false;
      if (ball.type==='explosive') {
        state.timeoutCount=0;
        events.push({ type:'explosion', ball, x:ball.x, y:ball.y });
        for (const o of state.balls) {
          if (o.alive && o.id!==ball.id && isInUpperHalf(o)) {
            const ep=moneyRound(o.value*o.multiplier*state.progressive*bs);
            state.totalWin=moneyRound(state.totalWin+ep);
            if (state.progressive<CONFIG.PROGRESSIVE_CAP) state.progressive++;
            events.push({ type:'exploded', ball:o, prize:ep });
            o.alive=false;
          }
        }
      }
    }
  }

  // Ball-ball collisions
  for (let i=0;i<state.balls.length;i++) {
    for (let j=i+1;j<state.balls.length;j++) {
      const b1=state.balls[i], b2=state.balls[j];
      if (!b1.alive||!b2.alive) continue;
      if (dist(b1.x,b1.y,b2.x,b2.y)<CONFIG.BALL_R*2) {
        const s1=b1.type!=='normal', s2=b2.type!=='normal';
        if (s1&&s2) {
          const dx=b2.x-b1.x, dy=b2.y-b1.y, d=Math.sqrt(dx*dx+dy*dy)||1;
          const nx=dx/d, ny=dy/d, ov=CONFIG.BALL_R*2-d;
          if (ov>0) { b1.x-=nx*ov*0.5; b1.y-=ny*ov*0.5; b2.x+=nx*ov*0.5; b2.y+=ny*ov*0.5; }
          b1.dx=-nx*CONFIG.SPEED; b1.dy=-ny*CONFIG.SPEED;
          b2.dx=nx*CONFIG.SPEED; b2.dy=ny*CONFIG.SPEED;
          randomizeBounce(b1,state.rng); randomizeBounce(b2,state.rng);
          continue;
        }
        if (s1) { b2.alive=false; const cp=moneyRound(state.betPerBall/5); state.totalWin=moneyRound(state.totalWin+cp); events.push({type:'collision',winner:b1,loser:b2,prize:cp}); continue; }
        if (s2) { b1.alive=false; const cp=moneyRound(state.betPerBall/5); state.totalWin=moneyRound(state.totalWin+cp); events.push({type:'collision',winner:b2,loser:b1,prize:cp}); continue; }
        if (b1.value===b2.value) {
          const prize=moneyRound(b1.value*2*(state.betPerBall/5));
          state.totalWin=moneyRound(state.totalWin+prize);
          events.push({ type:'double', b1, b2, prize });
          if (state.rng.nextDouble()<0.5) b2.alive=false; else b1.alive=false;
        } else {
          const cp=moneyRound(state.betPerBall/5); state.totalWin=moneyRound(state.totalWin+cp);
          const loser=b1.value<b2.value?b1:b2, winner=b1.value<b2.value?b2:b1;
          loser.alive=false;
          const dx=winner.x-loser.x, dy=winner.y-loser.y, d=Math.sqrt(dx*dx+dy*dy)||1;
          winner.dx=(dx/d)*CONFIG.SPEED; winner.dy=(dy/d)*CONFIG.SPEED;
          randomizeBounce(winner,state.rng);
          events.push({ type:'collision', winner, loser, prize:cp });
        }
      }
    }
  }

  // Timeouts
  for (const b of state.balls) {
    if (!b.alive && b.diedFromTimeout) {
      state.timeoutCount++;
      if (state.timeoutCount>=CONFIG.TIMEOUT_LIMIT) {
        state.progressive=1; state.timeoutCount=0;
        events.push({ type:'progressiveReset' });
      }
      b.diedFromTimeout=false;
    }
  }

  state.balls = state.balls.filter(b=>b.alive);

  // Auto-collect special balls
  if (state.balls.length>0 && !state.balls.some(b=>b.type==='normal')) {
    for (const b of state.balls) {
      if (b.alive) {
        const prize=moneyRound(b.value*b.multiplier*state.progressive*(state.betPerBall/5));
        state.totalWin=moneyRound(state.totalWin+prize);
        if (state.progressive<CONFIG.PROGRESSIVE_CAP) state.progressive++;
        events.push({ type:'autoCollect', ball:b, prize });
        b.alive=false;
      }
    }
    state.balls=[];
  }

  // End condition
  if (state.ballsSpawned>=state.numBalls && state.balls.length===0) {
    state.finished=true;
    events.push({ type:'gameEnd', totalWin:state.totalWin });
  }

  return events;
}

// ===== REPLAY =====

function replay(serverSeed, numBalls, inputLog, betPerBall=5) {
  const state = createInitialState(serverSeed, numBalls, betPerBall);
  let inputIdx=0, safety=0;
  const maxTicks = numBalls * CONFIG.MAX_TICKS_PER_BALL;
  while (!state.finished && safety<maxTicks) {
    let target=null;
    if (inputIdx<inputLog.length && inputLog[inputIdx].tick===state.tickCount+1) {
      target=inputLog[inputIdx].target; inputIdx++;
    } else if (state.tickCount>0) {
      target={ x:state.bumper.targetX, y:state.bumper.targetY };
    }
    tick(state,target); safety++;
  }
  return state;
}

// ===== FINISH =====

function finishGame(state) {
  const target={ x:state.bumper.targetX, y:state.bumper.targetY };
  let safety=0;
  while (!state.finished && safety<100000) { tick(state,target); safety++; }
}

// ===== EXPORT =====

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ENGINE_VERSION,
    CONFIG, BUMPER,
    UVS_PRNG,
    createInitialState, tick, replay, finishGame,
    clamp, fpRound, bytesToHex,
    sha256Hex, sha512Hex
  };
}
