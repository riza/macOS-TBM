"""Self-contained HTML security-research dashboard.

Embeds a slimmed view-model of the report as inline JSON and renders an
overview band, six interactive SVG charts, a sortable/filterable target table
and a per-target detail drawer — all with vanilla JS, no external requests.

The embedded payload drops what the page never renders (the full graph, raw
symbol tables) and caps the long list fields, which keeps the file an order of
magnitude smaller than the JSON report without losing anything on screen.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from utils.jsonio import dumps as _json_dumps

# How many entries of each long list survive into the HTML payload.
_LIB_CAP = 80
_STRING_CAP = 60
_OBJC_CAP = 60

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>macOS-TBM · Trust Boundary Map</title>
<style>
:root {
  --ink: #07090c;
  --ink-2: #0b0e13;
  --panel: #0f1319;
  --panel-2: #141922;
  --line: #1e2530;
  --line-2: #2b3441;
  --text: #dfe6ef;
  --text-2: #8b98aa;
  --text-3: #5b6879;

  --signal: #ffb020;      /* primary accent: amber signal */
  --signal-dim: #6b4a12;
  --cyan: #4fd6e0;
  --violet: #a98bff;
  --lime: #8fd14f;

  --hi: #ff6b5e;
  --med: #ffb020;
  --lo: #4fd6e0;
  --info: #6b7787;

  --mono: "SF Mono", "SFMono-Regular", Menlo, "Roboto Mono", monospace;
  --display: "Avenir Next Condensed", "Futura", "Helvetica Neue", sans-serif;
  --shadow: 0 18px 50px -20px rgba(0,0,0,.9);
}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background:
    radial-gradient(1100px 620px at 78% -12%, rgba(255,176,32,.075), transparent 62%),
    radial-gradient(820px 520px at 8% 4%, rgba(79,214,224,.055), transparent 60%),
    var(--ink);
  color: var(--text);
  font-family: var(--mono);
  font-size: 12.5px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
/* hairline grid texture */
body::before {
  content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background-image:
    linear-gradient(rgba(255,255,255,.014) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.014) 1px, transparent 1px);
  background-size: 56px 56px;
  mask-image: radial-gradient(circle at 50% 0%, #000 0%, transparent 78%);
}
.wrap { position: relative; z-index: 1; max-width: 1560px; margin: 0 auto; padding: 0 26px 120px; }

/* ---------- masthead ---------- */
header {
  position: sticky; top: 0; z-index: 40;
  display: flex; align-items: center; gap: 18px;
  padding: 14px 26px;
  background: #080a0e;
  border-bottom: 1px solid var(--line);
  box-shadow: 0 10px 24px -18px #000;
}
.mark { width: 30px; height: 30px; flex: none; }
.lockup { min-width: 0; overflow: hidden; }
.lockup h1 {
  font-family: var(--display); font-size: 19px; font-weight: 600;
  letter-spacing: .16em; text-transform: uppercase; margin: 0; line-height: 1.05;
}
.lockup h1 .tm { color: var(--signal); }
.lockup .sub {
  color: var(--text-3); font-size: 10.5px; letter-spacing: .1em; text-transform: uppercase;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.head-right { margin-left: auto; flex: none; display: flex; align-items: center; gap: 10px; }
.chip-static {
  border: 1px solid var(--line-2); border-radius: 999px; padding: 4px 11px;
  color: var(--text-2); font-size: 10.5px; letter-spacing: .09em; text-transform: uppercase;
}
.chip-static b { color: var(--signal); font-weight: 600; }

button, .btn {
  font-family: var(--mono); font-size: 11px; letter-spacing: .06em;
  background: var(--panel); color: var(--text-2);
  border: 1px solid var(--line-2); border-radius: 7px;
  padding: 6px 12px; cursor: pointer; transition: .16s ease;
}
button:hover, .btn:hover { color: var(--text); border-color: var(--signal); background: var(--panel-2); }

/* ---------- hero ---------- */
.hero { padding: 34px 0 22px; border-bottom: 1px solid var(--line); }
.eyebrow {
  font-family: var(--display); font-size: 11px; letter-spacing: .34em;
  text-transform: uppercase; color: var(--signal); margin-bottom: 12px;
}
.hero h2 {
  font-family: var(--display); font-weight: 500; text-transform: uppercase;
  letter-spacing: .04em; font-size: clamp(30px, 5.2vw, 60px);
  margin: 0 0 10px; line-height: .96; max-width: 20ch;
}
.hero h2 em { font-style: normal; color: var(--text-3); }
.hero p { color: var(--text-2); max-width: 74ch; margin: 0; font-size: 12px; }

/* ---------- stat tiles ---------- */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1px;
  background: var(--line); border: 1px solid var(--line); margin: 26px 0 0; }
.stat { background: var(--ink-2); padding: 16px 18px 14px; position: relative; overflow: hidden; }
.stat .lbl { color: var(--text-3); font-size: 10px; letter-spacing: .16em; text-transform: uppercase; }
.stat .num { font-family: var(--display); font-size: 40px; font-weight: 600; line-height: 1.05; letter-spacing: .01em; margin-top: 4px; }
.stat .meter { height: 3px; background: var(--line); margin-top: 10px; }
.stat .meter i { display: block; height: 100%; background: var(--signal); width: 0; transition: width 1.1s cubic-bezier(.16,1,.3,1); }
.stat .foot { color: var(--text-3); font-size: 10.5px; margin-top: 7px; }
.stat:nth-child(2) .num, .stat:nth-child(2) .meter i { color: var(--hi); background-color: var(--hi); }
.stat:nth-child(2) .num { background: none; color: var(--hi); }
.stat:nth-child(5) .num { color: var(--signal); }

/* ---------- section chrome ---------- */
.sec-head { display: flex; align-items: baseline; gap: 14px; margin: 44px 0 14px; }
.sec-head h3 {
  font-family: var(--display); font-size: 13px; letter-spacing: .26em;
  text-transform: uppercase; margin: 0; color: var(--text);
}
.sec-head .rule { flex: 1; height: 1px; background: var(--line); }
.sec-head .note { color: var(--text-3); font-size: 10.5px; letter-spacing: .08em; text-transform: uppercase; }

/* ---------- charts ---------- */
.charts { display: grid; grid-template-columns: repeat(12, 1fr); gap: 14px; }
.chart {
  grid-column: span 4; background: var(--panel); border: 1px solid var(--line);
  border-radius: 10px; padding: 14px 16px 12px; position: relative;
}
.chart.wide { grid-column: span 8; }
.chart.half { grid-column: span 6; }
.chart h4 {
  font-family: var(--display); font-size: 11.5px; letter-spacing: .2em; text-transform: uppercase;
  margin: 0 0 2px; color: var(--text);
}
.chart .hint { color: var(--text-3); font-size: 10px; letter-spacing: .05em; margin-bottom: 10px; }
.chart svg { display: block; width: 100%; max-height: 250px; overflow: visible; }
.chart .legend { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-top: 10px; }
.chart .legend span { color: var(--text-2); font-size: 10.5px; display: inline-flex; align-items: center; gap: 6px; cursor: pointer; }
.chart .legend i { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }
.chart .legend span.off { opacity: .35; text-decoration: line-through; }
.hit { cursor: pointer; }
.hit:hover .barfg, .hit:hover .arc { filter: brightness(1.25); }
.gridline { stroke: var(--line); stroke-width: 1; }
.axis { fill: var(--text-3); font-size: 9.5px; letter-spacing: .06em; font-family: var(--mono); }
.val { fill: var(--text-2); font-size: 10px; font-family: var(--mono); }
.barbg { fill: rgba(255,255,255,.045); }
.sel { stroke: var(--signal); stroke-width: 1; stroke-dasharray: 2 2; fill: none; }

#tip {
  position: fixed; z-index: 90; pointer-events: none; opacity: 0;
  background: #05070a; border: 1px solid var(--line-2); border-radius: 6px;
  padding: 6px 9px; font-size: 11px; color: var(--text); box-shadow: var(--shadow);
  transition: opacity .12s; max-width: 320px;
}
#tip b { color: var(--signal); }

/* ---------- filter bar ---------- */
.filters {
  position: sticky; top: 59px; z-index: 30;
  display: flex; flex-wrap: wrap; gap: 9px; align-items: center;
  padding: 11px 14px; margin: 0 0 12px;
  background: #0b0e13;
  border: 1px solid var(--line); border-radius: 10px;
}
.search { position: relative; flex: 1 1 300px; min-width: 220px; }
.search input {
  width: 100%; font-family: var(--mono); font-size: 12px;
  background: var(--ink); color: var(--text);
  border: 1px solid var(--line-2); border-radius: 7px; padding: 7px 10px 7px 28px;
}
.search input:focus { outline: none; border-color: var(--signal); }
.search svg { position: absolute; left: 8px; top: 8px; opacity: .5; }
.search kbd {
  position: absolute; right: 8px; top: 7px; color: var(--text-3); font-size: 10px;
  border: 1px solid var(--line-2); border-radius: 4px; padding: 0 5px;
}
input[type=number] {
  font-family: var(--mono); font-size: 12px; width: 104px;
  background: var(--ink); color: var(--text); border: 1px solid var(--line-2);
  border-radius: 7px; padding: 7px 9px;
}
.tog {
  display: inline-flex; align-items: center; gap: 6px; cursor: pointer;
  border: 1px solid var(--line-2); border-radius: 7px; padding: 6px 11px;
  color: var(--text-2); font-size: 11px; letter-spacing: .04em; user-select: none; transition: .16s;
}
.tog:hover { color: var(--text); }
.tog input { accent-color: var(--signal); margin: 0; }
.tog.on { border-color: var(--signal); color: var(--signal); background: rgba(255,176,32,.07); }
.pchips { display: flex; gap: 5px; }
.pchip {
  border: 1px solid var(--line-2); border-radius: 999px; padding: 5px 11px; cursor: pointer;
  font-size: 10.5px; letter-spacing: .1em; color: var(--text-3); transition: .16s; user-select: none;
}
.pchip.on { color: var(--ink); font-weight: 700; }
.pchip[data-p=HIGH].on { background: var(--hi); border-color: var(--hi); }
.pchip[data-p=MEDIUM].on { background: var(--med); border-color: var(--med); }
.pchip[data-p=LOW].on { background: var(--lo); border-color: var(--lo); }
.pchip[data-p=INFO].on { background: var(--info); border-color: var(--info); }
.count { margin-left: auto; color: var(--text-3); font-size: 11px; letter-spacing: .08em; }
.count b { color: var(--text); font-weight: 600; }
.activefilters { display: flex; flex-wrap: wrap; gap: 6px; width: 100%; }
.afilter {
  font-size: 10.5px; color: var(--signal); border: 1px solid var(--signal-dim);
  background: rgba(255,176,32,.08); border-radius: 999px; padding: 3px 9px; cursor: pointer;
}
.afilter:hover { background: rgba(255,176,32,.18); }

/* ---------- table ---------- */
.tablewrap { border: 1px solid var(--line); border-radius: 10px; overflow: hidden; background: var(--panel); }
.scroll { max-height: 74vh; overflow: auto; }
table { width: 100%; border-collapse: collapse; table-layout: fixed; }
col.c-score { width: 7%; } col.c-prio { width: 8%; } col.c-svc { width: 19%; }
col.c-bin { width: 20%; } col.c-user { width: 6%; } col.c-mach { width: 16%; }
col.c-ent { width: 5%; } col.c-val { width: 8%; } col.c-sink { width: 11%; }
thead th {
  position: sticky; top: 0; z-index: 5;
  background: #0c1016; color: var(--text-3);
  font-weight: 500; font-size: 10px; letter-spacing: .15em; text-transform: uppercase;
  text-align: left; padding: 10px; border-bottom: 1px solid var(--line-2);
  cursor: pointer; white-space: nowrap; user-select: none;
}
thead th:hover { color: var(--signal); }
thead th .car { opacity: 0; margin-left: 4px; }
thead th.sorted { color: var(--signal); }
thead th.sorted .car { opacity: 1; }
tbody td {
  padding: 8px 10px; border-bottom: 1px solid rgba(30,37,48,.7); vertical-align: middle;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
tbody tr { cursor: pointer; transition: background .12s; }
tbody tr:hover { background: rgba(255,176,32,.05); }
tbody tr.active { background: rgba(255,176,32,.1); box-shadow: inset 2px 0 0 var(--signal); }
.scorecell { display: flex; align-items: center; gap: 8px; }
.scorenum { font-family: var(--display); font-size: 17px; font-weight: 600; min-width: 30px; }
.scorebar { width: 42px; height: 3px; background: var(--line); }
.scorebar i { display: block; height: 100%; }
.svc { color: var(--text); }
.path { color: var(--text-3); font-size: 11px; direction: rtl; }
.path bdi { direction: ltr; }
.dots { display: inline-flex; gap: 3px; }
.dots i { width: 8px; height: 8px; border-radius: 2px; background: rgba(255,255,255,.07); }
.dots i.on { background: var(--violet); box-shadow: 0 0 6px rgba(169,139,255,.5); }
.badge {
  display: inline-block; padding: 1px 7px; border-radius: 999px;
  font-size: 10px; letter-spacing: .06em; margin: 1px 2px 1px 0; white-space: nowrap;
  border: 1px solid transparent;
}
.b-HIGH   { background: rgba(255,107,94,.14); color: var(--hi); border-color: rgba(255,107,94,.3); }
.b-MEDIUM { background: rgba(255,176,32,.13); color: var(--med); border-color: rgba(255,176,32,.28); }
.b-LOW    { background: rgba(79,214,224,.12); color: var(--lo); border-color: rgba(79,214,224,.28); }
.b-INFO   { background: rgba(107,119,135,.14); color: var(--info); border-color: rgba(107,119,135,.3); }
.b-sink { background: rgba(169,139,255,.12); color: var(--violet); border-color: rgba(169,139,255,.26); }
.b-fact { background: rgba(143,209,79,.12); color: var(--lime); border-color: rgba(143,209,79,.26); }
.b-heur { background: rgba(255,176,32,.1); color: var(--med); }
.b-unk  { background: rgba(107,119,135,.12); color: var(--text-3); }
.b-root { background: rgba(255,107,94,.1); color: var(--hi); }
.b-off { background: rgba(107,119,135,.2); color: var(--text-3); border-color: var(--line-2); margin-right: 6px; }
.b-val { border-style: solid; }
.sinkrow { margin: 0 0 14px; }
.sinkhead { display: flex; align-items: center; gap: 9px; }
.sinkname { font-family: var(--display); letter-spacing: .14em; font-size: 12px; min-width: 132px; }
.meterbar { flex: 1; max-width: 220px; height: 6px; background: var(--line); border-radius: 3px; overflow: hidden; }
.meterbar i { display: block; height: 100%; background: linear-gradient(90deg, var(--violet), var(--signal)); }
.evlist { list-style: none; margin: 5px 0 0; padding: 0 0 0 8px; border-left: 1px solid var(--line); }
.evlist li { margin: 2px 0; color: var(--text-2); }
.evlist li::before { content: "\21b3"; color: var(--text-3); margin-right: 6px; }
.evkind {
  display: inline-block; min-width: 84px; font-size: 10px; letter-spacing: .1em;
  text-transform: uppercase; color: var(--text-3);
}
.ev-import .evkind { color: var(--lime); }
.ev-entitlement .evkind { color: var(--signal); }
.ev-objc .evkind { color: var(--cyan); }
.ev-token .evkind, .ev-weak-library .evkind { color: var(--text-3); opacity: .6; }
.aspects { display: flex; flex-wrap: wrap; gap: 5px; margin: 5px 0 0 141px; }
.aspect {
  font-size: 9.5px; letter-spacing: .1em; text-transform: uppercase;
  color: var(--violet); border: 1px solid rgba(169,139,255,.3);
  background: rgba(169,139,255,.08); border-radius: 3px; padding: 1px 6px;
}
.aspect.sm { text-transform: none; letter-spacing: .04em; opacity: .75; }
.vtable { width: 100%; border-collapse: collapse; }
.vtable td { padding: 4px 8px 4px 0; vertical-align: top; border: none; }
.vtable tr.unseen { opacity: .55; }
.vtable .vmark { width: 18px; color: var(--lime); }
.vtable tr.unseen .vmark { color: var(--text-3); }
.vtable .vw { color: var(--signal); width: 42px; }
.hoodsvg { width: 100%; max-height: none; margin-top: 6px; }
.hoodsvg .gl { font-family: var(--mono); font-size: 10.5px; fill: var(--text); }
.hoodsvg .gs { font-family: var(--mono); font-size: 9px; fill: var(--text-3); }
.looked { display: block; color: var(--text-3); font-size: 10.5px; }
.dim { color: var(--text-3); }
.empty { padding: 40px; text-align: center; color: var(--text-3); }

/* ---------- drawer ---------- */
#scrim {
  position: fixed; inset: 0; background: rgba(3,5,8,.66);
  opacity: 0; pointer-events: none; transition: opacity .25s; z-index: 60;
}
#scrim.open { opacity: 1; pointer-events: auto; }
#drawer {
  position: fixed; top: 0; right: 0; height: 100%; width: min(760px, 94vw);
  background: var(--ink-2); border-left: 1px solid var(--line-2);
  box-shadow: var(--shadow); z-index: 70;
  transform: translateX(102%); transition: transform .32s cubic-bezier(.16,1,.3,1);
  display: flex; flex-direction: column;
}
#drawer.open { transform: none; }
.dhead {
  padding: 16px 22px; border-bottom: 1px solid var(--line);
  display: flex; align-items: flex-start; gap: 12px;
  background: linear-gradient(180deg, rgba(255,176,32,.05), transparent);
}
.dhead h3 { font-family: var(--display); font-size: 18px; letter-spacing: .06em; margin: 0 0 4px; word-break: break-all; }
.dclose { margin-left: auto; flex: none; }
.dbody { overflow: auto; padding: 4px 22px 60px; }
.dbody h4 {
  font-family: var(--display); font-size: 10.5px; letter-spacing: .24em; text-transform: uppercase;
  color: var(--signal); margin: 24px 0 8px; padding-bottom: 6px; border-bottom: 1px solid var(--line);
}
.kv { display: grid; grid-template-columns: 168px 1fr; gap: 5px 14px; }
.kv .k { color: var(--text-3); }
.kv .v { color: var(--text); word-break: break-word; }
.dbody ul { margin: 6px 0; padding-left: 16px; }
.dbody li { margin: 4px 0; }
.dbody code { color: var(--cyan); font-size: 11.5px; word-break: break-all; }
.w { color: var(--signal); font-weight: 700; }
details > summary { cursor: pointer; color: var(--text-2); }
details > summary:hover { color: var(--signal); }
.scorebars { display: grid; gap: 4px; }
.scorerow { display: grid; grid-template-columns: 40px 1fr; align-items: center; gap: 10px; }
.scorerow .bar { height: 14px; background: rgba(255,176,32,.22); border-left: 2px solid var(--signal); }
.scorerow .txt { color: var(--text-2); }

/* reveal */
.rv { opacity: 0; transform: translateY(10px); animation: rise .7s cubic-bezier(.16,1,.3,1) forwards; }
@keyframes rise { to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) { .rv { animation: none; opacity: 1; transform: none; } html { scroll-behavior: auto; } }
@media (max-width: 1180px) { .chart, .chart.half { grid-column: span 6; } .chart.wide { grid-column: span 12; } }
@media (max-width: 820px) { .chart, .chart.wide, .chart.half { grid-column: span 12; } }
@media (max-width: 700px) {
  .wrap { padding: 0 14px 80px; }
  .kv { grid-template-columns: 1fr; }
  header { gap: 10px; padding: 12px 14px; }
  .lockup .sub { display: none; }
  .chip-static { display: none; }
  .filters { position: static; }
}
</style>
</head>
<body>

<header>
  <svg class="mark" viewBox="0 0 40 40" fill="none" aria-hidden="true">
    <path d="M20 3 L34 9 v12 c0 8-6 13.5-14 16-8-2.5-14-8-14-16V9z" stroke="#ffb020" stroke-width="1.4"/>
    <path d="M20 11 v18 M13 17 h14 M13 23 h14" stroke="#4fd6e0" stroke-width="1.1" opacity=".8"/>
    <circle cx="20" cy="20" r="2.4" fill="#ffb020"/>
  </svg>
  <div class="lockup">
    <h1>macOS<span class="tm">-TBM</span></h1>
    <div class="sub" id="meta"></div>
  </div>
  <div class="head-right">
    <div class="chip-static">scope <b id="scopechip">—</b></div>
    <button id="csv">Export CSV</button>
  </div>
</header>

<div class="wrap">

  <section class="hero rv">
    <div class="eyebrow">static · read-only · heuristic</div>
    <h2>Attack surface of the <em>launchd</em> service graph</h2>
    <p>Every launchd job on this host, ranked by how much privileged, reachable and sensitive surface it exposes. Findings marked FACT come from parsed metadata; HEURISTIC findings come from symbol and string indicators. Absence of a signal is never proof of safety.</p>
    <div class="stats" id="stats"></div>
  </section>

  <div class="sec-head rv" style="animation-delay:.08s">
    <h3>Signal overview</h3><div class="rule"></div>
    <div class="note">click any chart element to filter</div>
  </div>

  <section class="charts rv" style="animation-delay:.12s">
    <div class="chart wide"><h4>Score distribution</h4><div class="hint">bucketed by 10 · solid = current filter</div><svg id="c-hist" viewBox="0 0 640 190"></svg></div>
    <div class="chart"><h4>Priority mix</h4><div class="hint">filtered set</div><svg id="c-donut" viewBox="0 0 300 190"></svg><div class="legend" id="l-donut"></div></div>
    <div class="chart half"><h4>Sensitive subsystems</h4><div class="hint">bar shade = evidence confidence (solid HIGH → faint LOW)</div><svg id="c-sinks" viewBox="0 0 480 230"></svg></div>
    <div class="chart half"><h4>Findings by category</h4><div class="hint">FACT vs HEURISTIC vs UNKNOWN</div><svg id="c-find" viewBox="0 0 480 230"></svg><div class="legend" id="l-find"></div></div>
    <div class="chart half"><h4>IPC role</h4><div class="hint">how the job participates in XPC / Mach</div><svg id="c-ipc" viewBox="0 0 480 190"></svg></div>
    <div class="chart half"><h4>Top targets by score</h4><div class="hint">click a bar to open the dossier</div><svg id="c-top" viewBox="0 0 480 190"></svg></div>
  </section>

  <div class="sec-head rv" style="animation-delay:.16s">
    <h3>Target register</h3><div class="rule"></div>
    <div class="note">click a row for the full dossier</div>
  </div>

  <div class="filters rv" style="animation-delay:.18s">
    <div class="search">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#8b98aa" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/></svg>
      <input type="text" id="q" placeholder="label, binary, mach service, entitlement…" spellcheck="false">
      <kbd>/</kbd>
    </div>
    <input type="number" id="minScore" placeholder="min score" min="0">
    <div class="pchips" id="pchips"></div>
    <label class="tog" data-for="privOnly"><input type="checkbox" id="privOnly"> root only</label>
    <label class="tog" data-for="machOnly"><input type="checkbox" id="machOnly"> Mach/XPC</label>
    <label class="tog" data-for="noValid"><input type="checkbox" id="noValid"> no validation seen</label>
    <label class="tog" data-for="thirdParty"><input type="checkbox" id="thirdParty"> non-platform binary</label>
    <label class="tog" data-for="liveOnly"><input type="checkbox" id="liveOnly"> enabled only</label>
    <button id="reset">Reset</button>
    <div class="count"><b id="n">0</b> / <span id="ntot">0</span> targets</div>
    <div class="activefilters" id="sinkkey"></div>
    <div class="activefilters" id="afilters"></div>
  </div>

  <div class="tablewrap rv" style="animation-delay:.2s">
    <div class="scroll">
      <table id="tbl">
        <colgroup>
          <col class="c-score"><col class="c-prio"><col class="c-svc"><col class="c-bin">
          <col class="c-user"><col class="c-mach"><col class="c-ent"><col class="c-val"><col class="c-sink">
        </colgroup>
        <thead><tr>
          <th data-sort="score">Score<span class="car">▾</span></th>
          <th data-sort="priority">Priority<span class="car">▾</span></th>
          <th data-sort="label">Service<span class="car">▾</span></th>
          <th data-sort="binary">Binary<span class="car">▾</span></th>
          <th data-sort="user">Run as<span class="car">▾</span></th>
          <th data-sort="mach">Mach / XPC<span class="car">▾</span></th>
          <th data-sort="ent">Ents<span class="car">▾</span></th>
          <th data-sort="signals" title="static caller-validation evidence strength">Validation<span class="car">▾</span></th>
          <th data-sort="sinks" id="th-sinks">Sinks<span class="car">▾</span></th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </div>
</div>

<div id="tip"></div>
<div id="scrim"></div>
<aside id="drawer" aria-hidden="true">
  <div class="dhead">
    <div style="min-width:0">
      <h3 id="d-title">—</h3>
      <div id="d-sub" class="dim"></div>
    </div>
    <button class="dclose" id="dclose">Close ✕</button>
  </div>
  <div class="dbody" id="d-body"></div>
</aside>

<script>
const REPORT = __REPORT_JSON__;
const $ = (s) => document.querySelector(s);
const PRIOS = ["HIGH", "MEDIUM", "LOW", "INFO"];
const PCOL = { HIGH: "#ff6b5e", MEDIUM: "#ffb020", LOW: "#4fd6e0", INFO: "#6b7787" };
const LCOL = { FACT: "#8fd14f", HEURISTIC: "#ffb020", UNKNOWN: "#6b7787" };
const CONF = { HIGH: 1, MEDIUM: .55, LOW: .25 };
const VCLASSES = REPORT.validation_classes || {};
const VCOL = { STRONG: "#8fd14f", MEDIUM: "#ffb020", WEAK: "#4fd6e0", NONE_OBSERVED: "#6b7787" };
const NS = "http://www.w3.org/2000/svg";

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function el(tag, attrs, txt) {
  const n = document.createElementNS(NS, tag);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  if (txt != null) n.textContent = txt;
  return n;
}
function tipOn(node, html) {
  node.addEventListener("mousemove", e => {
    const t = $("#tip");
    t.innerHTML = html;
    t.style.opacity = 1;
    const w = t.offsetWidth, h = t.offsetHeight;
    t.style.left = Math.min(e.clientX + 14, innerWidth - w - 10) + "px";
    t.style.top = Math.max(10, e.clientY - h - 12) + "px";
  });
  node.addEventListener("mouseleave", () => { $("#tip").style.opacity = 0; });
}

/* ---------- view model ---------- */
const T = (REPORT.targets || []).map((t, i) => {
  const svc = t.service || {}, exe = t.executable || {}, cs = exe.codesign || {}, mo = exe.macho || {};
  const findings = t.findings || [];
  return {
    i, raw: t,
    score: t.score || 0,
    priority: t.priority || "INFO",
    label: svc.label || "",
    binary: svc.associated_executable || exe.path || "",
    user: svc.run_as_user || svc.run_as || "?",
    machList: svc.mach_services || [],
    mach: (svc.mach_services || []).length,
    ent: Object.keys(cs.entitlements || {}).length,
    signals: ["NONE_OBSERVED", "WEAK", "MEDIUM", "STRONG"].indexOf(t.validation || "NONE_OBSERVED"),
    sinkList: t.sensitive_sinks || [],
    sinks: (t.sensitive_sinks || []).length,
    assessments: t.sink_assessments || [],
    conf: Object.fromEntries((t.sink_assessments || []).map(a => [a.label, a.confidence])),
    validation: t.validation || "NONE_OBSERVED",
    vassess: t.validation_assessment || null,
    hood: t.neighbourhood || null,
    ipc: t.ipc_classification || "unknown",
    scope: svc.scope || "",
    platform: cs.platform_binary,
    enabled: svc.enabled !== false,
    findings,
    hay: [svc.label, svc.associated_executable, (svc.mach_services || []).join(" "),
          Object.keys(cs.entitlements || {}).join(" "), (t.entitlement_findings || []).join(" "),
          (mo.linked_libs || []).join(" ")].join(" ").toLowerCase(),
  };
});
const MAXSCORE = Math.max(1, ...T.map(t => t.score));
const MINSCORE = Math.min(0, ...T.map(t => t.score));
const SINK_ORDER = (() => {
  const c = {};
  T.forEach(t => t.sinkList.forEach(s => c[s] = (c[s] || 0) + 1));
  return Object.keys(c).sort((a, b) => c[b] - c[a]);
})();

/* ---------- state ---------- */
const S = {
  q: "", min: null, band: null, prio: new Set(), sink: new Set(), ipc: new Set(), level: new Set(),
  priv: false, mach: false, noValid: false, third: false, liveOnly: false,
  sortKey: "score", asc: false, selected: null,
};
let VIEW = T;

function match(t) {
  if (S.min !== null && t.score < S.min) return false;
  if (S.band && (t.score < S.band[0] || t.score >= S.band[1])) return false;
  if (S.prio.size && !S.prio.has(t.priority)) return false;
  if (S.ipc.size && !S.ipc.has(t.ipc)) return false;
  if (S.sink.size) { for (const s of S.sink) if (!t.sinkList.includes(s)) return false; }
  if (S.priv && t.user !== "root") return false;
  if (S.mach && !t.mach) return false;
  if (S.noValid && t.validation !== "NONE_OBSERVED") return false;
  if (S.third && t.platform !== false) return false;
  if (S.liveOnly && !t.enabled) return false;
  if (S.q && !t.hay.includes(S.q)) return false;
  return true;
}

function compare(a, b) {
  const dir = S.asc ? 1 : -1, k = S.sortKey;
  let av = a[k], bv = b[k];
  if (k === "priority") { av = PRIOS.indexOf(a.priority); bv = PRIOS.indexOf(b.priority); av = -av; bv = -bv; }
  if (typeof av === "string") { const c = av.localeCompare(bv); return c ? c * dir : a.score - b.score; }
  if (av < bv) return -dir;
  if (av > bv) return dir;
  return b.score - a.score;
}

/* ---------- stats ---------- */
function renderStats() {
  const s = REPORT.summary || {};
  const tot = s.total_services || T.length;
  const g = REPORT.graph_summary || {};
  const tiles = [
    ["Services mapped", tot, tot, T.filter(t => !t.enabled).length + " disabled / not loadable"],
    ["High priority", s.high_priority_targets ?? T.filter(t => t.priority === "HIGH").length, tot, "score ≥ HIGH threshold"],
    ["Root privileged", s.privileged_services ?? 0, tot, "run as uid 0"],
    ["Mach / XPC exposed", s.mach_xpc_services ?? 0, tot, "registered endpoints"],
    ["Private entitlements", s.interesting_entitlement_count ?? 0, s.interesting_entitlement_count ?? 1, g.edges ? g.nodes + " graph nodes · " + g.edges + " edges" : "high-value grants"],
  ];
  $("#stats").innerHTML = tiles.map(([l, n, d, f]) => `
    <div class="stat">
      <div class="lbl">${l}</div>
      <div class="num">${n}</div>
      <div class="meter"><i data-w="${Math.round(100 * Math.min(1, n / Math.max(1, d)))}"></i></div>
      <div class="foot">${f}</div>
    </div>`).join("");
  requestAnimationFrame(() => document.querySelectorAll(".stat .meter i")
    .forEach(i => { i.style.width = i.dataset.w + "%"; }));
  $("#meta").textContent = "generated " + (REPORT.generated_at || "") + " · " + (REPORT.tool || "");
  $("#scopechip").textContent = ((REPORT.meta || {}).scope) || "all";
}

/* ---------- charts ---------- */
function chartHist() {
  const svg = $("#c-hist"); svg.innerHTML = "";
  const W = 640, H = 190, PL = 34, PB = 26, PT = 12;
  const step = 10;
  const lo = Math.floor(MINSCORE / step) * step;
  const bins = Math.max(1, Math.ceil((MAXSCORE + 1 - lo) / step));
  const bin = (score) => Math.max(0, Math.min(bins - 1, Math.floor((score - lo) / step)));
  const tot = new Array(bins).fill(0), cur = new Array(bins).fill(0);
  T.forEach(t => tot[bin(t.score)]++);
  VIEW.forEach(t => cur[bin(t.score)]++);
  const max = Math.max(1, ...tot);
  const bw = (W - PL - 8) / bins;
  for (let i = 0; i <= 4; i++) {
    const y = PT + (H - PT - PB) * (i / 4);
    svg.appendChild(el("line", { x1: PL, x2: W, y1: y, y2: y, class: "gridline" }));
    svg.appendChild(el("text", { x: 0, y: y + 3, class: "axis" }, Math.round(max * (1 - i / 4))));
  }
  for (let i = 0; i < bins; i++) {
    const x = PL + i * bw, h = (H - PT - PB) * (tot[i] / max), hc = (H - PT - PB) * (cur[i] / max);
    const from = lo + i * step;
    const g = el("g", { class: "hit" });
    g.appendChild(el("rect", { x: x + 1, y: H - PB - h, width: bw - 2.5, height: Math.max(h, .5), class: "barbg" }));
    const c = from >= 100 ? PCOL.HIGH : from >= 60 ? PCOL.MEDIUM : from >= 30 ? PCOL.LOW : PCOL.INFO;
    g.appendChild(el("rect", { x: x + 1, y: H - PB - hc, width: bw - 2.5, height: Math.max(hc, cur[i] ? 1 : 0), fill: c, class: "barfg", opacity: .9 }));
    if (S.band && S.band[0] === from) g.appendChild(el("rect", { x: x - .5, y: PT - 4, width: bw, height: H - PB - PT + 6, class: "sel" }));
    tipOn(g, `<b>score ${from}–${from + step - 1}</b><br>${cur[i]} shown / ${tot[i]} total`);
    g.addEventListener("click", () => {
      S.band = (S.band && S.band[0] === from) ? null : [from, from + step];
      apply();
    });
    svg.appendChild(g);
    if (i % 2 === 0) svg.appendChild(el("text", { x: x + bw / 2, y: H - 8, class: "axis", "text-anchor": "middle" }, from));
  }
}

function chartDonut() {
  const svg = $("#c-donut"); svg.innerHTML = "";
  const cx = 150, cy = 92, r = 66, thick = 22;
  const counts = {}; PRIOS.forEach(p => counts[p] = 0);
  VIEW.forEach(t => counts[t.priority]++);
  const total = VIEW.length || 1;
  let a0 = -Math.PI / 2;
  PRIOS.forEach(p => {
    const frac = counts[p] / total;
    if (!counts[p]) return;
    const a1 = a0 + frac * Math.PI * 2;
    const big = frac > .5 ? 1 : 0;
    const p0 = [cx + r * Math.cos(a0), cy + r * Math.sin(a0)];
    const p1 = [cx + r * Math.cos(a1), cy + r * Math.sin(a1)];
    const g = el("g", { class: "hit" });
    const path = el("path", {
      d: `M${p0[0]} ${p0[1]} A${r} ${r} 0 ${big} 1 ${p1[0]} ${p1[1]}`,
      stroke: PCOL[p], "stroke-width": S.prio.has(p) ? thick + 6 : thick, fill: "none", class: "arc",
      opacity: (!S.prio.size || S.prio.has(p)) ? .95 : .3,
    });
    g.appendChild(path);
    tipOn(g, `<b>${p}</b><br>${counts[p]} targets · ${(frac * 100).toFixed(1)}%`);
    g.addEventListener("click", () => togglePrio(p));
    svg.appendChild(g);
    a0 = a1;
  });
  svg.appendChild(el("text", { x: cx, y: cy - 2, "text-anchor": "middle", fill: "#dfe6ef",
    style: "font-family:var(--display);font-size:30px;font-weight:600" }, VIEW.length));
  svg.appendChild(el("text", { x: cx, y: cy + 16, "text-anchor": "middle", class: "axis" }, "IN VIEW"));
  $("#l-donut").innerHTML = PRIOS.map(p =>
    `<span data-p="${p}" class="${S.prio.size && !S.prio.has(p) ? "off" : ""}"><i style="background:${PCOL[p]}"></i>${p} ${counts[p]}</span>`).join("");
  $("#l-donut").querySelectorAll("span").forEach(s => s.addEventListener("click", () => togglePrio(s.dataset.p)));
}

function hbars(svgSel, rows, opts) {
  // rows: [{key,label,total,cur,color,active}]
  const svg = $(svgSel); svg.innerHTML = "";
  const W = 480, PL = opts.pad || 116, rowH = opts.rowH || 24, top = 6;
  const max = Math.max(1, ...rows.map(r => r.total));
  rows.forEach((r, i) => {
    const y = top + i * rowH;
    const g = el("g", { class: "hit" });
    g.appendChild(el("rect", { x: PL, y, width: (W - PL - 40) * (r.total / max), height: rowH - 9, class: "barbg" }));
    g.appendChild(el("rect", { x: PL, y, width: Math.max(1, (W - PL - 40) * (r.cur / max)), height: rowH - 9, fill: r.color, class: "barfg", opacity: r.active === false ? .3 : .92 }));
    g.appendChild(el("text", { x: PL - 8, y: y + rowH - 18, "text-anchor": "end", class: "axis" }, r.label));
    g.appendChild(el("text", { x: PL + (W - PL - 40) * (r.total / max) + 6, y: y + rowH - 18, class: "val" }, r.cur));
    tipOn(g, `<b>${esc(r.label)}</b><br>${r.cur} shown / ${r.total} total${opts.tipsuffix || ""}`);
    if (opts.onclick) g.addEventListener("click", () => opts.onclick(r.key));
    svg.appendChild(g);
  });
  svg.setAttribute("viewBox", `0 0 ${W} ${Math.max(60, top + rows.length * rowH + 4)}`);
}

function chartSinks() {
  // Split each bar by confidence: a sink label is only as good as its evidence.
  const svg = $("#c-sinks"); svg.innerHTML = "";
  const all = {}, cur = {};
  T.forEach(t => t.sinkList.forEach(s => all[s] = (all[s] || 0) + 1));
  VIEW.forEach(t => t.assessments.forEach(a => {
    cur[a.label] = cur[a.label] || { HIGH: 0, MEDIUM: 0, LOW: 0 };
    cur[a.label][a.confidence]++;
  }));
  const keys = Object.keys(all).sort((a, b) => all[b] - all[a]);
  const W = 480, PL = 122, rowH = 27, top = 6;
  const max = Math.max(1, ...keys.map(k => all[k]));
  keys.forEach((k, i) => {
    const y = top + i * rowH, c = cur[k] || { HIGH: 0, MEDIUM: 0, LOW: 0 };
    const tot = c.HIGH + c.MEDIUM + c.LOW;
    svg.appendChild(el("rect", { x: PL, y, width: (W - PL - 44) * (all[k] / max), height: rowH - 9, class: "barbg" }));
    let x = PL;
    ["HIGH", "MEDIUM", "LOW"].forEach(cf => {
      if (!c[cf]) return;
      const w = (W - PL - 44) * (c[cf] / max);
      const g = el("g", { class: "hit" });
      g.appendChild(el("rect", { x, y, width: Math.max(1, w), height: rowH - 9, fill: "#a98bff",
        opacity: (!S.sink.size || S.sink.has(k)) ? CONF[cf] : CONF[cf] * .35, class: "barfg" }));
      tipOn(g, `<b>${esc(k)} · ${cf} confidence</b><br>${c[cf]} shown · ${tot} total in view · ${all[k]} overall<br>click to filter`);
      g.addEventListener("click", () => { S.sink.has(k) ? S.sink.delete(k) : S.sink.add(k); apply(); });
      svg.appendChild(g);
      x += w;
    });
    svg.appendChild(el("text", { x: PL - 8, y: y + rowH - 18, "text-anchor": "end", class: "axis" }, k));
    svg.appendChild(el("text", { x: PL + (W - PL - 44) * (all[k] / max) + 6, y: y + rowH - 18, class: "val" }, tot));
  });
  svg.setAttribute("viewBox", `0 0 ${W} ${Math.max(60, top + keys.length * rowH + 4)}`);
}

function chartIpc() {
  const all = {}, cur = {};
  T.forEach(t => all[t.ipc] = (all[t.ipc] || 0) + 1);
  VIEW.forEach(t => cur[t.ipc] = (cur[t.ipc] || 0) + 1);
  const rows = Object.keys(all).sort((a, b) => all[b] - all[a]).map(k => ({
    key: k, label: k.length > 26 ? k.slice(0, 25) + "…" : k, total: all[k], cur: cur[k] || 0,
    color: "#4fd6e0", active: !S.ipc.size || S.ipc.has(k),
  }));
  hbars("#c-ipc", rows, { pad: 170, rowH: 27, tipsuffix: " · click to filter", onclick: k => {
    S.ipc.has(k) ? S.ipc.delete(k) : S.ipc.add(k); apply();
  }});
}

function chartFindings() {
  const svg = $("#c-find"); svg.innerHTML = "";
  const agg = {};
  VIEW.forEach(t => t.findings.forEach(f => {
    const c = f.category || "other";
    agg[c] = agg[c] || { FACT: 0, HEURISTIC: 0, UNKNOWN: 0 };
    agg[c][f.level] = (agg[c][f.level] || 0) + 1;
  }));
  const cats = Object.keys(agg).sort((a, b) =>
    (agg[b].FACT + agg[b].HEURISTIC + agg[b].UNKNOWN) - (agg[a].FACT + agg[a].HEURISTIC + agg[a].UNKNOWN));
  const W = 480, PL = 132, rowH = 28, top = 6;
  const max = Math.max(1, ...cats.map(c => agg[c].FACT + agg[c].HEURISTIC + agg[c].UNKNOWN));
  cats.forEach((c, i) => {
    const y = top + i * rowH;
    let x = PL;
    ["FACT", "HEURISTIC", "UNKNOWN"].forEach(lv => {
      const n = agg[c][lv] || 0;
      if (!n) return;
      const w = (W - PL - 44) * (n / max);
      const g = el("g", { class: "hit" });
      g.appendChild(el("rect", { x, y, width: Math.max(w, 1), height: rowH - 11, fill: LCOL[lv], class: "barfg",
        opacity: (!S.level.size || S.level.has(lv)) ? .9 : .28 }));
      tipOn(g, `<b>${esc(c)} · ${lv}</b><br>${n} findings`);
      g.addEventListener("click", () => { S.level.has(lv) ? S.level.delete(lv) : S.level.add(lv); apply(); });
      svg.appendChild(g);
      x += w;
    });
    svg.appendChild(el("text", { x: PL - 8, y: y + rowH - 20, "text-anchor": "end", class: "axis" }, c.replace(/_/g, " ")));
    svg.appendChild(el("text", { x: x + 6, y: y + rowH - 20, class: "val" },
      agg[c].FACT + agg[c].HEURISTIC + agg[c].UNKNOWN));
  });
  svg.setAttribute("viewBox", `0 0 ${W} ${Math.max(60, top + cats.length * rowH + 4)}`);
  $("#l-find").innerHTML = ["FACT", "HEURISTIC", "UNKNOWN"].map(lv =>
    `<span data-l="${lv}" class="${S.level.size && !S.level.has(lv) ? "off" : ""}"><i style="background:${LCOL[lv]}"></i>${lv}</span>`).join("");
  $("#l-find").querySelectorAll("span").forEach(s => s.addEventListener("click", () => {
    const lv = s.dataset.l; S.level.has(lv) ? S.level.delete(lv) : S.level.add(lv); apply();
  }));
}

function chartTop() {
  const rows = VIEW.slice(0, 8).map(t => ({
    key: t.i, label: t.label.replace(/^com\.apple\./, "…").slice(0, 30),
    total: Math.max(0, t.score), cur: Math.max(0, t.score),
    color: PCOL[t.priority],
  }));
  hbars("#c-top", rows, { pad: 168, rowH: 23, tipsuffix: "", onclick: i => openDrawer(T.find(t => t.i === i)) });
  if (!rows.length) $("#c-top").innerHTML = '<text x="12" y="30" class="axis">no targets in filter</text>';
}

/* ---------- table ---------- */
function renderRows() {
  const body = $("#rows");
  if (!VIEW.length) { body.innerHTML = `<tr><td colspan="9" class="empty">No target matches the current filter.</td></tr>`; return; }
  const frag = VIEW.map(t => {
    const machTxt = t.mach
      ? t.machList.slice(0, 2).map(m => `<span class="badge b-LOW">${esc(m.replace(/^com\.apple\./, "…"))}</span>`).join("") +
        (t.mach > 2 ? `<span class="dim"> +${t.mach - 2}</span>` : "")
      : '<span class="dim">—</span>';
    return `<tr data-i="${t.i}" title="${esc(t.label)}">
      <td><div class="scorecell"><span class="scorenum" style="color:${PCOL[t.priority]}">${t.score}</span>
        <span class="scorebar"><i style="width:${Math.max(0, Math.round(100 * t.score / MAXSCORE))}%;background:${PCOL[t.priority]}"></i></span></div></td>
      <td><span class="badge b-${t.priority}">${t.priority}</span></td>
      <td class="svc" title="${esc(t.label)}">${t.enabled ? "" : '<span class="badge b-off">off</span>'}${esc(t.label)}</td>
      <td class="path" title="${esc(t.binary)}"><bdi>${esc(t.binary)}</bdi></td>
      <td>${t.user === "root" ? '<span class="badge b-root">root</span>' : `<span class="dim">${esc(t.user)}</span>`}</td>
      <td title="${esc(t.machList.join(", "))}">${machTxt}</td>
      <td>${t.ent ? `<span class="badge b-heur">${t.ent}</span>` : '<span class="dim">—</span>'}</td>
      <td title="static caller-validation evidence, not a safety verdict"><span class="badge b-val"
        style="color:${VCOL[t.validation]};border-color:${VCOL[t.validation]}44;background:${VCOL[t.validation]}18">${
        t.validation === "NONE_OBSERVED" ? "none seen" : t.validation.toLowerCase()}</span></td>
      <td title="${esc(t.assessments.length
          ? t.assessments.map(a => `${a.label}: ${a.confidence} (${a.score})`).join("\n")
          : "no sensitive subsystem indicators")}">
        <span class="dots">${SINK_ORDER.map(s => t.conf[s]
          ? `<i class="on" style="opacity:${CONF[t.conf[s]]}"></i>`
          : `<i></i>`).join("")}</span></td>
    </tr>`;
  }).join("");
  body.innerHTML = frag;
  body.querySelectorAll("tr").forEach(tr => tr.addEventListener("click", () => {
    openDrawer(T[+tr.dataset.i]);
  }));
}

/* ---------- drawer ---------- */
function kv(items) {
  return `<div class="kv">${items.map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${v}</div>`).join("")}</div>`;
}
function list(arr, fmt) {
  if (!arr || !arr.length) return '<div class="dim">none</div>';
  return `<ul>${arr.map(fmt || (x => `<li>${esc(x)}</li>`)).join("")}</ul>`;
}

/* ---------- trust-boundary neighbourhood ---------- */
function neighbourhoodPanel(t) {
  const h = t.hood;
  if (!h || (!h.provides.length && !h.looks_up.length)) return "";
  const inbound = h.provides.filter(p => p.clients.length);
  const W = 700, ROW = 26, PAD = 12;
  const rows = Math.max(1, inbound.reduce((n, p) => n + Math.max(1, Math.min(p.clients.length, 6)), 0));
  const H = PAD * 2 + rows * ROW;
  const colC = 208, colM = 300, colS = 470;   // clients | mach service | this service

  let y = PAD + 14, svg = "";
  inbound.forEach(p => {
    const shown = p.clients.slice(0, 6);
    const first = y;
    shown.forEach(c => {
      const colour = c.privileged ? "#ff6b5e" : "#4fd6e0";
      svg += `<line x1="${colC}" y1="${y - 4}" x2="${colM}" y2="${y - 4}" stroke="${colour}" stroke-width="1"
                ${c.evidence === "string" ? 'stroke-dasharray="3 3"' : ""} opacity=".55"/>`;
      svg += `<text x="${colC - 8}" y="${y}" text-anchor="end" class="gl" fill="${colour}">${esc(c.label)}</text>`;
      svg += `<text x="${colC - 8}" y="${y + 10}" text-anchor="end" class="gs">${esc(c.run_as)} · ${esc(c.evidence)}</text>`;
      y += ROW;
    });
    if (p.clients.length > shown.length)
      svg += `<text x="${colC - 8}" y="${y}" text-anchor="end" class="gs">+${p.clients.length - shown.length} more</text>`,
      y += ROW;
    const mid = (first + y) / 2 - 8;
    svg += `<rect x="${colM}" y="${mid - 11}" width="150" height="20" rx="4" fill="rgba(169,139,255,.14)" stroke="#a98bff"/>`;
    svg += `<text x="${colM + 75}" y="${mid + 3}" text-anchor="middle" class="gl" fill="#a98bff">${esc(shorten(p.mach, 22))}</text>`;
    svg += `<line x1="${colM + 150}" y1="${mid - 1}" x2="${colS}" y2="${H / 2}" stroke="#ffb020" stroke-width="1" opacity=".55"/>`;
  });
  svg += `<rect x="${colS}" y="${H / 2 - 15}" width="180" height="30" rx="4" fill="rgba(255,176,32,.14)" stroke="#ffb020"/>`;
  svg += `<text x="${colS + 90}" y="${H / 2 - 1}" text-anchor="middle" class="gl" fill="#ffb020">${esc(shorten(t.label, 24))}</text>`;
  svg += `<text x="${colS + 90}" y="${H / 2 + 11}" text-anchor="middle" class="gs">${esc(t.user)} · validation ${esc(t.validation)}</text>`;

  const out = h.looks_up.slice(0, 12);
  return `
    <h4>trust boundary &mdash; who reaches this service</h4>
    ${inbound.length ? `<svg class="hoodsvg" viewBox="0 0 ${W} ${H}"><g>${svg}</g></svg>
      <div class="dim" style="margin-top:4px">Solid line = the client's entitlement names this service
        (Apple-declared). Dashed = the service name appears in the client binary.
        <span style="color:#ff6b5e">red</span> = the client is root too,
        <span style="color:#4fd6e0">cyan</span> = it crosses a privilege boundary.</div>`
      : '<div class="dim">No client was observed naming this service.</div>'}
    ${out.length ? `<div style="margin-top:12px"><b class="dim">this service names ${h.looks_up.length} other endpoint(s)</b>
      <ul class="evlist">${out.map(o =>
        `<li><span class="evkind">${o.privileged ? "root" : "user"}</span> <code>${esc(o.mach)}</code>
         <span class="dim">${esc(o.provider)}${o.validation ? " · validation " + esc(o.validation) : ""} · ${esc(o.evidence)}</span></li>`).join("")}
      ${h.looks_up.length > out.length ? `<li class="dim">+${h.looks_up.length - out.length} more</li>` : ""}</ul></div>` : ""}
  `;
}

function shorten(s, n) {
  s = String(s).replace(/^com\.apple\./, "…");
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function openDrawer(t) {
  if (!t) return;
  const r = t.raw, svc = r.service || {}, exe = r.executable || {}, cs = exe.codesign || {}, mo = exe.macho || {};
  const ent = cs.entitlements || {};
  S.selected = t.i;
  document.querySelectorAll("#rows tr").forEach(tr => tr.classList.toggle("active", +tr.dataset.i === t.i));

  $("#d-title").innerHTML = `${esc(svc.label || t.label)} <span class="badge b-${t.priority}">${t.priority}</span>`;
  $("#d-sub").innerHTML = `score <b class="w">${t.score}</b> · ${esc(svc.service_type || "?")} · ${esc(svc.scope || "?")} · ${esc(t.ipc)}` +
    (t.enabled ? "" : ` · <span class="badge b-off">disabled</span>`);

  const maxW = Math.max(1, ...(r.reasons || []).map(x => Math.abs(x.weight || 0)));
  const reasons = (r.reasons || []).map(x =>
    `<div class="scorerow"><span class="w">${x.weight >= 0 ? "+" : ""}${x.weight}</span>
     <span class="bar" style="width:${Math.max(6, 100 * Math.abs(x.weight) / maxW)}%"></span></div>
     <div class="scorerow"><span></span><span class="txt">${esc(x.reason)}</span></div>`).join("");

  const findings = (r.findings || []).map(f => {
    const cls = f.level === "FACT" ? "b-fact" : f.level === "HEURISTIC" ? "b-heur" : "b-unk";
    return `<li><span class="badge ${cls}">${esc(f.level)}</span> <span class="dim">[${esc(f.category)}]</span> ${esc(f.message)}` +
      (f.evidence ? `<div class="dim" style="margin-left:8px">↳ ${esc(f.evidence)}</div>` : "") + `</li>`;
  }).join("");

  const entKeys = Object.keys(ent);
  const interesting = new Set(r.entitlement_findings || []);
  const entHtml = entKeys.length
    ? `<ul>${entKeys.sort((a, b) => (interesting.has(b) - interesting.has(a)) || a.localeCompare(b)).map(k =>
        `<li>${interesting.has(k) ? '<span class="badge b-HIGH">private</span> ' : ""}<code>${esc(k)}</code> = <code>${esc(JSON.stringify(ent[k]))}</code></li>`).join("")}</ul>`
    : '<div class="dim">none</div>';

  const libs = mo.linked_libs || [], strs = mo.interesting_strings || [], objc = mo.objc_classes || [];

  $("#d-body").innerHTML = `
    ${neighbourhoodPanel(t)}

    <h4>launchd metadata</h4>
    ${kv([
      ["plist", `<code>${esc(svc.plist_path)}</code>`],
      ["load state", `${t.enabled ? '<span class="badge b-fact">enabled</span>' : '<span class="badge b-off">disabled</span>'} <span class="dim">${esc(svc.enabled_derivation || "")}</span>`],
      ["program", `<code>${esc(svc.program || (svc.program_arguments || []).join(" "))}</code>`],
      ["run as", `${t.user === "root" ? '<span class="badge b-root">root</span>' : esc(t.user)} <span class="dim">${esc(svc.run_as_derivation || "")}</span>`],
      ["user / group", `${esc(svc.user_name || "—")} / ${esc(svc.group_name || "—")}`],
      ["mach services", (svc.mach_services || []).length ? (svc.mach_services || []).map(m => `<span class="badge b-LOW">${esc(m)}</span>`).join(" ") : '<span class="dim">—</span>'],
      ["sockets", Object.keys(svc.sockets || {}).length ? `<code>${esc(JSON.stringify(svc.sockets))}</code>` : '<span class="dim">—</span>'],
      ["keep alive / run at load", `${esc(JSON.stringify(svc.keep_alive))} / ${esc(String(svc.run_at_load))}`],
    ])}

    <h4>code signing</h4>
    ${kv([
      ["signed", cs.is_signed ? '<span class="badge b-fact">yes</span>' : (cs.is_signed === false ? '<span class="badge b-HIGH">no</span>' : '<span class="badge b-unk">unknown</span>')],
      ["identifier", `<code>${esc(cs.signer_identifier || "—")}</code>`],
      ["team", esc(cs.team_identifier || "—")],
      ["platform binary", cs.platform_binary == null ? '<span class="badge b-unk">unknown</span>' : (cs.platform_binary ? "yes" : '<span class="badge b-MEDIUM">no</span>')],
      ["flags", (cs.flags || []).join(", ") || "—"],
      ["authority", (cs.authority || []).map(esc).join(" &larr; ") || "—"],
      ["architectures", (mo.architectures || []).join(", ") || "—"],
    ])}

    <h4>why it is interesting</h4>
    ${list(r.why_interesting || r.research_leads)}

    <h4>score contributors</h4>
    <div class="scorebars">${reasons || '<div class="dim">no contributors</div>'}</div>

    <h4>sensitive subsystems &mdash; evidence</h4>
    ${t.assessments.length ? t.assessments.map(a => `
      <div class="sinkrow">
        <div class="sinkhead">
          <span class="sinkname">${esc(a.label)}</span>
          <span class="badge b-${a.confidence}">${a.confidence}</span>
          <span class="meterbar"><i style="width:${Math.min(100, a.score * 3.5)}%"></i></span>
          <span class="dim">${a.score}</span>
        </div>
        ${(a.aspects || []).length ? `<div class="aspects">${a.aspects.map(x =>
          `<span class="aspect">${esc(x)}</span>`).join("")}</div>` : ""}
        <ul class="evlist">${a.evidence.map(e =>
          `<li class="ev-${esc(e.kind)}"><span class="evkind">${esc(e.kind)}</span> <code>${esc(e.match)}</code>${
            e.aspect ? ` <span class="aspect sm">${esc(e.aspect)}</span>` : ""}${
            e.weight ? ` <span class="dim">+${e.weight}</span>` : ' <span class="dim">(not counted)</span>'}</li>`).join("")}</ul>
      </div>`).join("") : '<div class="dim">no sink indicators</div>'}

    <h4>caller validation &mdash; evidence</h4>
    <div class="sinkhead" style="margin-bottom:10px">
      <span class="sinkname">CALLER VALIDATION</span>
      <span class="badge b-val" style="color:${VCOL[t.validation]};border-color:${VCOL[t.validation]}44;background:${VCOL[t.validation]}18">${esc(t.validation)}</span>
      <span class="meterbar"><i style="width:${Math.min(100, ((t.vassess || {}).score || 0) * 5)}%"></i></span>
      <span class="dim">${(t.vassess || {}).score || 0}</span>
    </div>
    ${t.vassess ? `
    <table class="vtable">
      ${Object.entries((t.vassess.evidence || []).reduce((m, e) => {
          (m[e.aspect || "other"] = m[e.aspect || "other"] || []).push(e); return m; }, {}))
        .sort((a, b) => Math.max(...b[1].map(e => e.weight)) - Math.max(...a[1].map(e => e.weight)))
        .map(([cls, evs]) => `<tr class="seen">
          <td class="vmark">&#10003;</td><td>${esc(cls)}</td>
          <td class="vw">+${Math.max(...evs.map(e => e.weight))}</td>
          <td><code>${evs.map(e => esc(e.match)).join(", ")}</code></td></tr>`).join("")}
      ${(t.vassess.not_observed || []).map(m => {
          const info = VCLASSES[m.class] || {};
          return `<tr class="unseen">
          <td class="vmark">?</td><td>${esc(m.class)}</td>
          <td class="vw">+${m.weight ?? info.weight ?? 0}</td>
          <td class="dim">${esc(info.description || "")} <span class="looked">looked for: ${esc(info.looked_for || "")}</span></td></tr>`;
        }).join("")}
    </table>` : ""}
    <div class="dim" style="margin-top:8px">Static evidence only. It does not affect the score, and
      &ldquo;not observed&rdquo; is a statement about this scanner, not about the service.</div>

    <h4>entitlements (${entKeys.length})</h4>
    ${entHtml}

    <h4>findings (${(r.findings || []).length})</h4>
    <ul>${findings || "<li>none</li>"}</ul>

    <h4>manual research questions</h4>
    ${list(r.research_questions)}

    <h4>binary detail</h4>
    <details><summary>linked libraries (${libs.length}${mo.linked_libs_count && mo.linked_libs_count > libs.length ? " of " + mo.linked_libs_count : ""})</summary>
      ${list(libs, l => `<li><code>${esc(l)}</code></li>`)}</details>
    <details><summary>interesting strings (${strs.length}${mo.interesting_strings_count && mo.interesting_strings_count > strs.length ? " of " + mo.interesting_strings_count : ""})</summary>
      ${list(strs, l => `<li><code>${esc(l)}</code></li>`)}</details>
    <details><summary>ObjC classes (${objc.length}${mo.objc_classes_count && mo.objc_classes_count > objc.length ? " of " + mo.objc_classes_count : ""})</summary>
      ${list(objc, l => `<li><code>${esc(l)}</code></li>`)}</details>
    <div class="dim" style="margin-top:12px">imported symbols: ${mo.imported_symbols_count ?? "?"} · exported: ${mo.exported_symbols_count ?? "?"}</div>
  `;
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  $("#scrim").classList.add("open");
  $("#d-body").scrollTop = 0;
}
function closeDrawer() {
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#scrim").classList.remove("open");
}

/* ---------- filters plumbing ---------- */
function togglePrio(p) { S.prio.has(p) ? S.prio.delete(p) : S.prio.add(p); apply(); }

function renderActiveFilters() {
  const bits = [];
  if (S.band) bits.push(["score band " + S.band[0] + "–" + (S.band[1] - 1), () => S.band = null]);
  S.prio.forEach(p => bits.push(["priority " + p, () => S.prio.delete(p)]));
  S.sink.forEach(s => bits.push(["sink " + s, () => S.sink.delete(s)]));
  S.ipc.forEach(i => bits.push(["ipc " + i, () => S.ipc.delete(i)]));
  S.level.forEach(l => bits.push(["level " + l + " (chart only)", () => S.level.delete(l)]));
  const box = $("#afilters");
  box.innerHTML = bits.map((b, i) => `<span class="afilter" data-i="${i}">${esc(b[0])} ✕</span>`).join("");
  box.querySelectorAll(".afilter").forEach(n => n.addEventListener("click", () => { bits[+n.dataset.i][1](); apply(); }));
  document.querySelectorAll(".pchip").forEach(c => c.classList.toggle("on", S.prio.has(c.dataset.p)));
  document.querySelectorAll(".tog").forEach(l => l.classList.toggle("on", $("#" + l.dataset.for).checked));
}

function apply() {
  VIEW = T.filter(match).sort(compare);
  $("#n").textContent = VIEW.length;
  $("#ntot").textContent = T.length;
  renderRows();
  chartHist(); chartDonut(); chartSinks(); chartIpc(); chartFindings(); chartTop();
  renderActiveFilters();
  document.querySelectorAll("thead th").forEach(th => {
    th.classList.toggle("sorted", th.dataset.sort === S.sortKey);
    th.querySelector(".car").textContent = S.asc ? "▴" : "▾";
  });
}

function exportCsv() {
  const head = ["score", "priority", "label", "binary", "run_as", "enabled", "scope", "plist",
                "mach_services", "entitlements", "validation", "validation_score",
                "validation_classes", "validation_evidence", "sinks", "sink_confidence",
                "sink_aspects", "sink_evidence", "ipc"];
  const q = v => `"${String(v == null ? "" : v).replace(/"/g, '""')}"`;
  const lines = [head.join(",")].concat(VIEW.map(t => [
    t.score, t.priority, t.label, t.binary, t.user, t.enabled ? "enabled" : "disabled", t.scope,
    (t.raw.service || {}).plist_path || "",
    t.machList.join(" "), t.ent, t.validation,
    (t.vassess || {}).score || 0,
    ((t.vassess || {}).classes || []).join(" "),
    ((t.vassess || {}).evidence_text || []).join("; "),
    t.sinkList.join(" "),
    t.assessments.map(a => `${a.label}=${a.confidence}(${a.score})`).join(" "),
    t.assessments.map(a => `${a.label}:[${(a.aspects || []).join(",")}]`).join(" "),
    t.assessments.map(a => `${a.label}:[${(a.evidence_text || []).join("; ")}]`).join(" "),
    t.ipc,
  ].map(q).join(",")));
  const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url; a.download = "trust-boundary-targets.csv"; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function init() {
  renderStats();
  $("#pchips").innerHTML = PRIOS.map(p => `<span class="pchip" data-p="${p}">${p}</span>`).join("");
  $("#th-sinks").title = "sink columns, left to right: " + SINK_ORDER.join(", ");
  $("#sinkkey").innerHTML = '<span class="dim" style="font-size:10.5px">sink matrix →</span>' +
    SINK_ORDER.map((s, i) => `<span class="afilter" data-s="${esc(s)}" style="opacity:.9">${i + 1}. ${esc(s)}</span>`).join("");
  $("#sinkkey").querySelectorAll("[data-s]").forEach(n => n.addEventListener("click", () => {
    const k = n.dataset.s; S.sink.has(k) ? S.sink.delete(k) : S.sink.add(k); apply();
  }));
  document.querySelectorAll(".pchip").forEach(c => c.addEventListener("click", () => togglePrio(c.dataset.p)));

  $("#q").addEventListener("input", e => { S.q = e.target.value.trim().toLowerCase(); apply(); });
  $("#minScore").addEventListener("input", e => {
    const v = parseInt(e.target.value, 10);
    S.min = Number.isNaN(v) ? null : v;
    apply();
  });
  const flags = { privOnly: "priv", machOnly: "mach", noValid: "noValid", thirdParty: "third", liveOnly: "liveOnly" };
  Object.entries(flags).forEach(([id, key]) =>
    $("#" + id).addEventListener("change", e => { S[key] = e.target.checked; apply(); }));

  document.querySelectorAll("thead th").forEach(th => th.addEventListener("click", () => {
    const k = th.dataset.sort;
    // text columns read best A→Z, numeric columns worst-first
    const textCol = k === "label" || k === "binary" || k === "user";
    if (S.sortKey === k) S.asc = !S.asc; else { S.sortKey = k; S.asc = textCol; }
    apply();
  }));

  $("#reset").addEventListener("click", () => {
    S.q = ""; S.min = null; S.band = null;
    S.prio.clear(); S.sink.clear(); S.ipc.clear(); S.level.clear();
    S.priv = S.mach = S.noValid = S.third = S.liveOnly = false;
    $("#q").value = ""; $("#minScore").value = "";
    ["privOnly", "machOnly", "noValid", "thirdParty", "liveOnly"].forEach(id => $("#" + id).checked = false);
    S.sortKey = "score"; S.asc = false; apply();
  });

  $("#csv").addEventListener("click", exportCsv);
  $("#dclose").addEventListener("click", closeDrawer);
  $("#scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeDrawer();
    if (e.key === "/" && document.activeElement !== $("#q")) { e.preventDefault(); $("#q").focus(); }
  });
  addEventListener("resize", () => { chartHist(); chartDonut(); chartSinks(); chartIpc(); chartFindings(); chartTop(); });
  apply();
}
init();
</script>
</body>
</html>
"""


def _slim_macho(macho: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only what the dashboard renders; symbol tables become counts."""
    out = {k: v for k, v in macho.items() if k not in
           ("imported_symbols", "exported_symbols", "linked_libs", "interesting_strings", "objc_classes")}
    out["linked_libs"] = (macho.get("linked_libs") or [])[:_LIB_CAP]
    out["interesting_strings"] = (macho.get("interesting_strings") or [])[:_STRING_CAP]
    out["objc_classes"] = (macho.get("objc_classes") or [])[:_OBJC_CAP]
    out.setdefault("linked_libs_count", len(macho.get("linked_libs") or []))
    out.setdefault("interesting_strings_count", len(macho.get("interesting_strings") or []))
    out.setdefault("objc_classes_count", len(macho.get("objc_classes") or []))
    return out


def _neighbourhoods(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Per-service trust-boundary neighbourhood, small enough to embed.

    The full graph is far too big for the page, but the part that matters for one
    target is tiny: which Mach services it provides, who names them, and which
    services it names in turn.
    """
    nodes = {n["id"]: n for n in graph.get("nodes") or []}
    provider_of: Dict[str, str] = {}
    provides: Dict[str, List[str]] = {}
    for edge in graph.get("edges") or []:
        if edge.get("type") == "PROVIDES":
            provider_of[edge["target"]] = edge["source"]
            provides.setdefault(edge["source"], []).append(edge["target"])

    exec_service = {n["id"]: (n.get("data") or {}).get("service")
                    for n in nodes.values() if n.get("type") == "Executable"}

    inbound: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
    outbound: Dict[str, List[Dict[str, Any]]] = {}
    for edge in graph.get("edges") or []:
        if edge.get("type") != "LOOKS_UP":
            continue
        mach_id, client_id = edge["target"], edge["source"]
        evidence = (edge.get("data") or {}).get("evidence", "?")
        client = nodes.get(client_id) or {}
        cdata = client.get("data") or {}
        provider_id = provider_of.get(mach_id)
        mach_label = (nodes.get(mach_id) or {}).get("label", mach_id)

        if provider_id:
            entry = inbound.setdefault(provider_id, {}).setdefault(mach_label, [])
            entry.append({
                "label": exec_service.get(client_id) or client.get("label", client_id),
                "run_as": cdata.get("run_as_user", "?"),
                "privileged": bool(cdata.get("privileged")),
                "evidence": evidence,
            })

        client_service = exec_service.get(client_id)
        if client_service:
            pdata = ((nodes.get(provider_id) or {}).get("data") or {}) if provider_id else {}
            outbound.setdefault(f"service:{client_service}", []).append({
                "mach": mach_label,
                "provider": (nodes.get(provider_id) or {}).get("label", "") if provider_id else "",
                "privileged": bool(pdata.get("privileged")),
                "validation": pdata.get("validation", ""),
                "evidence": evidence,
            })

    out: Dict[str, Dict[str, Any]] = {}
    for svc_id in set(list(inbound) + list(outbound) + list(provides)):
        label = (nodes.get(svc_id) or {}).get("label")
        if not label:
            continue
        out[label] = {
            "provides": [{"mach": (nodes.get(m) or {}).get("label", m),
                          "clients": inbound.get(svc_id, {}).get((nodes.get(m) or {}).get("label", m), [])}
                         for m in provides.get(svc_id, [])],
            "looks_up": outbound.get(svc_id, []),
        }
    return out


def _view_model(report: Dict[str, Any]) -> Dict[str, Any]:
    """Strip the payload down to what the HTML actually shows."""
    out = {k: v for k, v in report.items() if k not in ("targets", "graph")}
    graph = report.get("graph") or {}
    out["graph_summary"] = {
        "nodes": len(graph.get("nodes") or []),
        "edges": len(graph.get("edges") or []),
    }
    hoods = _neighbourhoods(graph)

    # Every target lists the validation classes it lacks, with identical prose.
    # Hoist that into one table and leave the per-target rows as class + weight.
    classes: Dict[str, Dict[str, Any]] = {}
    for t in report.get("targets") or []:
        for miss in ((t.get("validation_assessment") or {}).get("not_observed") or []):
            classes.setdefault(miss.get("class", ""), {
                "weight": miss.get("weight", 0),
                "description": miss.get("description", ""),
                "looked_for": miss.get("looked_for", ""),
            })
    out["validation_classes"] = classes
    targets = []
    for t in report.get("targets") or []:
        t2 = dict(t)
        exe = dict(t.get("executable") or {})
        if exe.get("macho"):
            exe["macho"] = _slim_macho(exe["macho"])
        t2["executable"] = exe
        # research_leads is usually a verbatim copy of why_interesting
        if t2.get("research_leads") == t2.get("why_interesting"):
            t2.pop("research_leads", None)
        va = t2.get("validation_assessment")
        if va and va.get("not_observed"):
            va = dict(va)
            va["not_observed"] = [{"class": m.get("class")} for m in va["not_observed"]]
            t2["validation_assessment"] = va
        hood = hoods.get(t2.get("label"))
        if hood and (hood["provides"] or hood["looks_up"]):
            t2["neighbourhood"] = hood
        targets.append(t2)
    out["targets"] = targets
    return out


def write_html_report(path: str, report: Dict[str, Any]) -> None:
    """Render *report* to a self-contained HTML file at *path*."""
    data = _json_dumps(_view_model(report), indent=None).replace("</", "<\\/")
    html = _TEMPLATE.replace("__REPORT_JSON__", data)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
