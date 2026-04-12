# paddla-engine

PADDLA physics arcade engine — UVS 1.0 compatible.

**Version:** 9.0.1  
**Protocol:** [UVS v1](https://github.com/constarik/uvs)  
**PRNG:** ChaCha20 (RFC 8439) + SHA-512

## Install

```bash
npm install paddla-engine
```

## Usage

```js
const { createInitialState, tick, replay, ENGINE_VERSION } = require('paddla-engine');

const state = createInitialState(serverSeed, numBalls, betPerBall);
const events = tick(state, { x: 4.5, y: 2.0 });
```

## Exports

- `createInitialState(serverSeed, numBalls, betPerBall)`
- `tick(state, bumperTarget)`
- `replay(serverSeed, numBalls, inputLog, betPerBall)`
- `finishGame(state)`
- `UVS_PRNG` — ChaCha20-based PRNG
- `sha256Hex`, `sha512Hex`
- `ENGINE_VERSION`, `CONFIG`, `BUMPER`
