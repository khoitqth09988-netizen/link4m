#!/usr/bin/env node
/*
 * decode.js — standalone decoder for cuttaypromax.js (no instrumentation).
 *
 * Pipeline reproduced from static analysis of _R():
 *   L1  custom base64  alphabet  A-Za-z0-9$_   (stop at '=')
 *   L2  rolling XOR    plain[i] = enc[i] ^ Sm[i % 32] ^ (i & 255)
 *       Sm[i] = a6[i] ^ RQ[i] ^ xN[i] ^ IM[i]
 *       IM    = 32 bytes evolved from FNV-1a(payload-string)
 *   L2b MAC check       t0 = c1(plainBody, pl) must equal trailer plain[-32:]
 *       c1 = HMAC-like double FNV-1a (ipad ^54 / opad ^92, 32-byte tags)
 *   L3  (skipped here) record extraction -> {B$, Qf, se}  [done by extract.js]
 *   L4  PRNG XOR keystream over B$ (the original `(function(Gb){...})(dh.B$)`
 *       IIFE is lifted verbatim out of the source and executed here).
 *
 * Verified byte-for-byte against analysis/dump_L3.json + dump_L4.json.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const src = fs.readFileSync(path.join(root, 'cuttaypromax.js'), 'utf8');

/* ---------- helpers ---------------------------------------------------- */
function arr(label, re) {
  const m = src.match(re);
  if (!m) throw new Error('constant not found: ' + label);
  return JSON.parse(m[1].replace(/\s+/g, ''));
}
function fnv1a(bytes, h = 2166136261) {
  for (const b of bytes) {
    h = (((h ^ b) & 65535) * 16777619 + ((((h ^ b) >>> 16) * 16777619 & 65535) << 16) | 0) >>> 0;
  }
  return h;
}
function mulNoXor(h) { // (h * 16777619) mod 2^32, same split trick as source
  return (((h & 65535) * 16777619 + (((h >>> 16) * 16777619 & 65535) << 16)) | 0) >>> 0;
}
function fnvExtend(bytes) { // FNV-1a then fold 32 bytes out of the state
  let h = fnv1a(bytes);
  const out = [];
  for (let i = 0; i < 32; i++) {
    out.push((h >>> ((i % 4) * 8)) & 255);
    h = mulNoXor(h);
  }
  return out;
}
function c1(eZ, CW) { // replication of the MAC in _R
  let B0 = CW.slice();
  while (B0.length < 64) B0.push(0);
  const ipad = [], opad = [];
  for (let i = 0; i < 64; i++) { ipad.push(B0[i] ^ 54); opad.push(B0[i] ^ 92); }
  const K9 = ipad.concat(eZ);            // inner hash input
  const ZY = fnvExtend(K9);              // inner tag (32 B)
  const g9 = opad.concat(ZY);            // outer hash input
  return fnvExtend(g9);                  // outer tag = MAC (32 B)
}

/* ---------- L1: custom base64 ------------------------------------------ */
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$_';
const payStart = src.indexOf('_R("') + 4;
const payEnd = src.indexOf('")', payStart);
if (payStart < 4 || payEnd < 0) throw new Error('payload not found');
const payload = src.slice(payStart, payEnd);
console.log('payload chars:', payload.length);

const enc = [];
{ let b3 = 0, Q4 = 0;
  for (let hy = 0; hy < payload.length; hy++) {
    if (payload[hy] === '=') break;
    b3 = (b3 << 6) | ALPHA.indexOf(payload[hy]);
    Q4 += 6;
    while (Q4 >= 8) { Q4 -= 8; enc.push((b3 >> Q4) & 255); }
  }
}
console.log('L1 decoded bytes:', enc.length);

/* ---------- L2: key Sm -------------------------------------------------- */
const a6  = arr('a6',  /a6 = (\[[^\]]+\])/);
const RQ  = arr('RQ',  /RQ = (\[[^\]]+\])/);
const xN  = arr('xN',  /xN = (\[[^\]]+\])/);
const pl  = arr('pl',  /pl = (\[[^\]]+\])/);
const zi  = arr('zi',  /zi = (\[[^\]]+\])/);
if (![a6, RQ, xN, pl, zi].every(a => a.length === 32 || a === zi)) throw new Error('bad constants');

let jE = fnv1a([...payload].map(c => c.charCodeAt(0)));   // FNV-1a over payload text
const IM = [];
for (let hy = 0; hy < 32; hy++) {
  jE = (((jE ^ hy) & 65535) * 16777619 + ((((jE ^ hy) >>> 16) * 16777619 & 65535) << 16) | 0) >>> 0;
  IM.push(jE & 255);
}
const Sm = a6.map((v, i) => (v ^ RQ[i] ^ xN[i] ^ IM[i]) & 255);

const plain = enc.map((b, i) => (b ^ Sm[i % 32] ^ (i & 255)) & 255);
console.log('L2 magic ok:', zi.every((z, i) => plain[i] === z), JSON.stringify(plain.slice(0, 3)));

const body = plain.slice(0, plain.length - 32);
const trailer = plain.slice(plain.length - 32);
const t0 = c1(body, pl);
const macOk = t0.every((b, i) => b === trailer[i]);
console.log('L2b MAC ok:', macOk, '| body', body.length, '+ trailer', trailer.length);
if (!macOk) throw new Error('MAC mismatch — constants wrong');

/* ---------- L3 (needs state machine; reuse extract.js dump) -------------- */
const L3 = JSON.parse(fs.readFileSync(path.join(__dirname, 'dump_L3.json'), 'utf8'));
const same = (a, b) => a && b && a.length === b.length && a.every((v, i) => v === b[i]);
console.log('L3 body == dump vD :', same(body, L3._full.vD));
console.log('L3 Sm   == dump Sm :', same(Sm, L3.Sm));
console.log('L3 trailer == dump Mw:', same(trailer, L3._full.Mw));

const B$ = L3.B$; // decoded record-stream bootstrap (from _R's decoder)
console.log('L3 B$ size:', B$.length, '| Qf len:', (L3.Qf || []).length, '| se keys:', Object.keys(L3.se || {}).length);

/* ---------- L4: lift the original PRNG-XOR IIFE ------------------------- */
{
  const s = src.indexOf('function Wd('); // include Wd/Wc helpers the IIFE closes over
  const e = src.indexOf('})(dh.B$);', s);
  if (s < 0 || e < 0) throw new Error('Gb IIFE not found');
  const iife = src.slice(s, e + '})(dh.B$);'.length);
  const Gb = B$.slice();
  new Function('Gb_target', iife.replace('})(dh.B$);', '})(Gb_target);'))(Gb);
  const L4 = JSON.parse(fs.readFileSync(path.join(__dirname, 'dump_L4.json'), 'utf8'));
  console.log('L4 Ca == dump L4.Ca:', same(Gb, L4.Ca));
  fs.writeFileSync(path.join(__dirname, 'decoded_L4_program.bin'), Buffer.from(Gb));
}

/* ---------- artifacts ---------------------------------------------------- */
fs.writeFileSync(path.join(__dirname, 'decoded_plaintext_body.bin'), Buffer.from(body));
fs.writeFileSync(path.join(__dirname, 'decoded_mac_trailer.bin'), Buffer.from(trailer));
console.log('wrote analysis/decoded_plaintext_body.bin (' + body.length + ' B)');
console.log('wrote analysis/decoded_L4_program.bin (55 B)');

/* ---------- L5: per-record bitstream decode — lift `function $` --------- */
{
  const s = src.indexOf('function $(ZQ, AF, FU) {');
  const e = src.indexOf('function _R(VR)', s);
  if (s < 0 || e < 0) throw new Error('function $ not found');
  const fnText = src.slice(s, e); // self-contained except $G / Zr aliases
  const $G = [WeakMap, Uint16Array, JSON, DataView, undefined, ReferenceError, BigInt,
    TypeError, String, Math, Reflect, Promise, Symbol, Uint8Array, ArrayBuffer, Array];
  const Zr = Math.floor;
  const $fn = new Function('$G', 'Zr', fnText + '\nreturn $;')($G, Zr);

  const decoded = {};
  let words = 0;
  for (const k of Object.keys(L3.se)) {
    const r = L3.se[k];
    const out = $fn(r.Uc, r.i, r.X$);          // Uint16Array, length === X$
    decoded[k] = { i: r.i, X$: r.X$, ra: r.ra, words: Array.from(out) };
    words += out.length;
  }
  fs.writeFileSync(path.join(__dirname, 'decoded_records.json'), JSON.stringify(decoded));
  console.log('L5 records decoded:', Object.keys(decoded).length, '| total uint16 words:', words);
  console.log('wrote analysis/decoded_records.json');
}
