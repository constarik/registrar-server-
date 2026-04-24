/**
 * NOISORE Engine — Server-side (no DOM)
 * Pure game logic for Move Sync G=1
 */
'use strict';

class NoisoreEngine {
  constructor(rows, cols, maxH, rotate, rng) {
    this.ROWS = rows;
    this.COLS = cols;
    this.MAX_H = maxH || 10;
    this.ROTATE = rotate;
    this.rng = rng; // ChaCha20 instance
    this.grid = [];
    this.dropNum = 0;
    this.moves = []; // audit trail
  }

  gameRng() { return this.rng.nextFloat(); }

  initGrid() {
    this.grid = [];
    for (let r = 0; r < this.ROWS; r++) {
      this.grid[r] = [];
      for (let c = 0; c < this.COLS; c++) {
        this.grid[r][c] = 1 + Math.floor(this.gameRng() * this.MAX_H);
      }
    }
  }

  copyGrid() {
    return this.grid.map(row => row.slice());
  }

  chooseNext(row, col) {
    const cands = [];
    for (let dc = -1; dc <= 1; dc++) {
      const nc = col + dc;
      if (nc >= 0 && nc < this.COLS) cands.push({ c: nc, h: this.grid[row + 1][nc] });
    }
    const nz = cands.filter(x => x.h > 0);
    if (nz.length === 0) return cands[Math.floor(this.gameRng() * cands.length)].c;
    const w = nz.map(x => 1 / x.h);
    const tw = w.reduce((a, b) => a + b, 0);
    let r = this.gameRng() * tw;
    for (let i = 0; i < nz.length; i++) {
      r -= w[i];
      if (r <= 0) return nz[i].c;
    }
    return nz[nz.length - 1].c;
  }

  hasChannel() {
    for (let c = 0; c < this.COLS; c++) {
      if (this.grid[0][c] === 0) {
        if (this._dfs(0, c, {})) return true;
      }
    }
    return false;
  }

  _dfs(row, col, vis) {
    const k = row + '-' + col;
    if (vis[k]) return false;
    vis[k] = true;
    if (this.grid[row][col] !== 0) return false;
    if (row === this.ROWS - 1) return true;
    for (let dc = -1; dc <= 1; dc++) {
      const nc = col + dc;
      if (nc >= 0 && nc < this.COLS && this._dfs(row + 1, nc, vis)) return true;
    }
    return false;
  }

  findChannelCells() {
    const ch = {};
    for (let c = 0; c < this.COLS; c++) {
      if (this.grid[0][c] === 0) {
        const path = [];
        if (this._dfsCollect(0, c, {}, path)) {
          for (const p of path) ch[p] = true;
        }
      }
    }
    return ch;
  }

  _dfsCollect(row, col, vis, path) {
    const k = row + '-' + col;
    if (vis[k]) return false;
    vis[k] = true;
    if (this.grid[row][col] !== 0) return false;
    path.push(k);
    if (row === this.ROWS - 1) return true;
    let found = false;
    for (let dc = -1; dc <= 1; dc++) {
      const nc = col + dc;
      if (nc >= 0 && nc < this.COLS) {
        const before = path.length;
        if (this._dfsCollect(row + 1, nc, vis, path)) found = true;
        else path.length = before;
      }
    }
    if (!found) path.pop();
    return found;
  }

  rotateGridCW() {
    const S = this.ROWS;
    const ng = [];
    for (let r = 0; r < S; r++) {
      ng[r] = [];
      for (let c = 0; c < S; c++) {
        ng[r][c] = this.grid[S - 1 - c][r];
      }
    }
    this.grid = ng;
  }

  fillRowIfChannel() {
    let fills = 0;
    while (this.hasChannel()) {
      const row = Math.floor(this.gameRng() * this.ROWS);
      for (let c = 0; c < this.COLS; c++) {
        this.grid[row][c] = 1 + Math.floor(this.gameRng() * this.MAX_H);
      }
      fills++;
      if (fills > 10) break;
    }
    return fills;
  }

  randDrop() {
    return 1 + Math.floor(this.gameRng() * this.MAX_H);
  }

  /**
   * Apply a single drop. Returns { path, washed, remaining }
   */
  applyDrop(col, dropPower) {
    let power = dropPower, c = col;
    const path = [];
    for (let row = 0; row < this.ROWS && power > 0; row++) {
      if (this.grid[row][c] === 0) {
        path.push({ row, col: c, action: 'flow', power });
        if (row < this.ROWS - 1) c = this.chooseNext(row, c);
        continue;
      }
      const h = this.grid[row][c];
      if (power >= h) {
        power -= h;
        this.grid[row][c] = 0;
        path.push({ row, col: c, action: 'wash', was: h, power });
      } else {
        this.grid[row][c] -= power;
        path.push({ row, col: c, action: 'hit', was: h, now: h - power, power: 0 });
        power = 0;
      }
      if (power > 0 && row < this.ROWS - 1) c = this.chooseNext(row, c);
    }
    this.dropNum++;
    return { path, remaining: power };
  }
}

module.exports = { NoisoreEngine };
