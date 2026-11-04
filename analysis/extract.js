#!/usr/bin/env node
/*
 * extract.js — instrument cuttaypromax.js to dump every layer of its
 * obfuscation pipeline without executing the final payload program.
 *
 * Patches applied (3 text anchors):
 *   A) case 60063 in _R(): snapshot locals before returning {B$, Qf, se}
 *   B) case 526122: dump the XOR-196 string table `_` before running
 *   C) final W0 invocation: snapshot dh.B$ (after layer-4 PRNG XOR),
 *      then hand the program an EMPTY config so it is never really run.
 *
 * Output: analysis/strings.json, analysis/dump_L3.json, analysis/dump_L4.json
 */
'use strict';
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const src = fs.readFileSync(path.join(root, 'cuttaypromax.js'), 'utf8');

let out = src;
let patched = 0;

function replaceOnce(text, needle, repl) {
  const i = text.indexOf(needle);
  if (i < 0) throw new Error('anchor not found: ' + JSON.stringify(needle.slice(0, 70)));
  if (text.indexOf(needle, i + 1) >= 0) throw new Error('anchor not unique: ' + needle.slice(0, 70));
  patched++;
  return text.slice(0, i) + repl + text.slice(i + needle.length);
}

/* ---- A) dump inside _R at its normal return ---------------------------- */
const anchorA =
  '          case 60063:\n' +
  '            return {\n' +
  '              B$: _x,\n' +
  '              Qf: Dn,\n' +
  '              se: pO\n' +
  '            };';
out = replaceOnce(out, anchorA,
  '          case 60063:\n' +
  '            try {\n' +
  '              globalThis.__L3 = {\n' +
  '                B$: Array.from(_x),\n' +
  '                Qf: Dn,\n' +
  '                se: pO,\n' +
  '                qN: Array.from(qN),\n' +
  '                vD: vD ? Array.from(vD) : null,\n' +
  '                Mw: Mw ? Array.from(Mw) : null,\n' +
  '                t0: t0 ? Array.from(t0) : null,\n' +
  '                vJ: vJ,\n' +
  '                Sm: Sm ? Array.from(Sm) : null,\n' +
  '                zi: typeof zi !== "undefined" ? zi : null\n' +
  '              };\n' +
  '            } catch (e) { globalThis.__L3_ERR = String(e && e.stack || e); }\n' +
  '            return {\n' +
  '              B$: _x,\n' +
  '              Qf: Dn,\n' +
  '              se: pO\n' +
  '            };');

/* ---- B) dump string table before the payload is decoded ---------------- */
const anchorB =
  '        case 526122:\n' +
  '          (function (dh) {';
out = replaceOnce(out, anchorB,
  '        case 526122:\n' +
  '          try { globalThis.__STRINGS = JSON.parse(JSON.stringify(_.U)); } catch (e) {}\n' +
  '          (function (dh) {');

/* ---- C) snapshot dh.B$ at final call, run program with empty config ---- */
{
  const j = out.indexOf('Ca: dh.B$,');
  if (j < 0) throw new Error('anchor C field not found');
  const start = out.lastIndexOf('})({', j);
  if (start < 0) throw new Error('anchor C open not found');
  const end = out.indexOf('});', j);
  if (end < 0) throw new Error('anchor C close not found');
  const replacement =
    '})((globalThis.__L4 = { Ca: Array.from(dh.B$), Qf: dh.Qf, se: dh.se }, ' +
    '{ Ca: [], Vd: null, Fb: [], s: null, b$: {} }));';
  // replace the whole original call text '})({...});'
  out = out.slice(0, start) + replacement + out.slice(end + 3);
  patched++;
}

const tmp = path.join(__dirname, '.instrumented.js');
fs.writeFileSync(tmp, out);
console.log('patched anchors:', patched);

/* ---- run -------------------------------------------------------------- */
try {
  require(tmp);
} catch (e) {
  console.log('execution ended with (expected) error:', String(e && e.message || e).slice(0, 200));
}

function save(name, value) {
  const p = path.join(__dirname, name);
  fs.writeFileSync(p, JSON.stringify(value));
  console.log('wrote', name, fs.statSync(p).size, 'bytes');
}

if (globalThis.__L3_ERR) console.log('L3 dump error:', globalThis.__L3_ERR);
if (globalThis.__STRINGS) save('strings.json', globalThis.__STRINGS);
if (globalThis.__L3) {
  const L = globalThis.__L3;
  save('dump_L3.json', {
    vJ: L.vJ,
    sizes: {
      qN: L.qN && L.qN.length,
      vD: L.vD && L.vD.length,
      Mw: L.Mw && L.Mw.length,
      t0: L.t0 && L.t0.length,
      B$_x: L.B$.length,
      Qf: Array.isArray(L.Qf) ? L.Qf.length : String(L.Qf),
      se_keys: L.se && typeof L.se === 'object' ? Object.keys(L.se).length : String(L.se),
    },
    Sm: L.Sm,
    zi: L.zi,
    mac_ok: L.t0 && L.Mw ? L.t0.every((b, i) => b === L.Mw[i]) : null,
    head_qN: L.qN && L.qN.slice(0, 16),
    head_vD: L.vD && L.vD.slice(0, 16),
    head_B$: L.B$.slice(0, 32),
    B$: L.B$.slice(0, 4096), // first 4 KiB preview; full copy in L4 after xor
    Qf: L.Qf,
    se: L.se,
    _full: { B$: L.B$, qN: L.qN, vD: L.vD, Mw: L.Mw, t0: L.t0 },
  });
}
if (globalThis.__L4) {
  const L = globalThis.__L4;
  save('dump_L4.json', {
    sizes: { Ca: L.Ca.length, Qf: Array.isArray(L.Qf) ? L.Qf.length : null },
    head_Ca: L.Ca.slice(0, 64),
    Ca: L.Ca,
    Qf: L.Qf,
    se: L.se,
  });
}
console.log('done');
