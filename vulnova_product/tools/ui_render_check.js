#!/usr/bin/env node
/*
 * DOM-SHIM RENDER CHECK — THIS IS NOT A SCREENSHOT.
 *
 * There is no browser in this sandbox. This harness parses index.html into a
 * minimal DOM, executes the real static/app.js against a live server, and
 * asserts what the application produced. It proves the rendering *logic*; it
 * cannot prove visual layout, CSS correctness or accessibility in a real
 * browser. Do not describe its output as a screenshot.
 *
 *   node tools/ui_render_check.js --base http://127.0.0.1:8000 \
 *        --dump reports/improvement1_2/rendered_markup
 */

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const args = process.argv.slice(2);
function arg(name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : fallback;
}
const BASE = arg("--base", "http://127.0.0.1:8000").replace(/\/$/, "");
const DUMP = arg("--dump", null);
const ROOT = path.resolve(__dirname, "..");

const results = [];
function check(name, condition, detail) {
  results.push({ name, ok: !!condition, detail: detail || "" });
  console.log(`  [${condition ? "PASS" : "FAIL"}] ${name}${condition ? "" : "  " + (detail || "")}`);
}

/* ------------------------------------------------------------------ DOM */

class Node {
  constructor(tag) {
    this.tagName = (tag || "").toUpperCase();
    this.children = [];
    this.attributes = {};
    this.listeners = {};
    this.className = "";
    this.id = "";
    this._text = "";
    this.parentNode = null;
  }
  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }
  removeChild(child) {
    this.children = this.children.filter((c) => c !== child);
    child.parentNode = null;
  }
  get firstChild() {
    return this.children[0] || null;
  }
  setAttribute(key, value) {
    this.attributes[key] = String(value);
    if (key === "class") this.className = String(value);
    if (key === "id") this.id = String(value);
  }
  getAttribute(key) {
    return this.attributes[key] === undefined ? null : this.attributes[key];
  }
  addEventListener(type, fn) {
    (this.listeners[type] = this.listeners[type] || []).push(fn);
  }
  set textContent(value) {
    this._text = String(value);
    this.children = [];
  }
  get textContent() {
    return this._text + this.children.map((c) => c.textContent).join("");
  }
  get classList() {
    const node = this;
    const list = () => node.className.split(/\s+/).filter(Boolean);
    return {
      add(cls) {
        const parts = list();
        if (!parts.includes(cls)) parts.push(cls);
        node.className = parts.join(" ");
      },
      remove(cls) {
        node.className = list().filter((c) => c !== cls).join(" ");
      },
      contains(cls) {
        return list().includes(cls);
      },
    };
  }
  querySelectorAll(selector) {
    const [parent, child] = selector.split(/\s+/);
    const out = [];
    const walk = (node) => {
      for (const kid of node.children) {
        if (kid.tagName === child.toUpperCase() &&
            node.tagName === parent.toUpperCase()) {
          out.push(kid);
        }
        walk(kid);
      }
    };
    walk(this.ownerDocument ? this.ownerDocument.root : this);
    return out;
  }
  *descendants() {
    for (const kid of this.children || []) {
      yield kid;
      if (typeof kid.descendants === "function") yield* kid.descendants();
    }
  }
}

class TextNode {
  constructor(text) {
    this._text = String(text);
    this.children = [];
    this.tagName = "#text";
  }
  get textContent() {
    return this._text;
  }
  set textContent(v) {
    this._text = String(v);
  }
}

const VOID = new Set(["meta", "link", "input", "br", "img", "hr", "source"]);
const ATTR_RE = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*"([^"]*)"|\s*=\s*'([^']*)')?/g;

function parseHTML(html) {
  const root = new Node("#root");
  let current = root;
  let i = 0;

  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt === -1) {
      const text = html.slice(i);
      if (text.trim()) current.appendChild(new TextNode(text));
      break;
    }
    if (lt > i) {
      const text = html.slice(i, lt);
      if (text.trim()) current.appendChild(new TextNode(text));
    }
    const gt = html.indexOf(">", lt);
    if (gt === -1) break;
    const raw = html.slice(lt + 1, gt).trim();
    i = gt + 1;

    if (raw.startsWith("!--") || raw.startsWith("!")) continue;
    if (raw.startsWith("/")) {
      if (current.parentNode) current = current.parentNode;
      continue;
    }
    const selfClosing = raw.endsWith("/");
    const nameMatch = raw.match(/^([a-zA-Z0-9-]+)/);
    if (!nameMatch) continue;
    const tag = nameMatch[1].toLowerCase();
    const node = new Node(tag);
    const attrText = raw.slice(nameMatch[0].length);
    let match;
    ATTR_RE.lastIndex = 0;
    while ((match = ATTR_RE.exec(attrText)) !== null) {
      const key = match[1];
      const value = match[2] !== undefined ? match[2] : (match[3] !== undefined ? match[3] : "");
      node.setAttribute(key, value);
    }
    current.appendChild(node);
    if (!VOID.has(tag) && !selfClosing) current = node;
  }
  return root;
}

function makeDocument(html) {
  const root = parseHTML(html);
  const byId = new Map();
  for (const node of root.descendants()) {
    if (node.attributes && node.attributes.id) byId.set(node.attributes.id, node);
  }
  const body = [...root.descendants()].find((n) => n.tagName === "BODY") || root;
  const doc = {
    root,
    body,
    readyState: "complete",
    createElement: (tag) => {
      const node = new Node(tag);
      node.ownerDocument = doc;
      return node;
    },
    createTextNode: (text) => new TextNode(text),
    getElementById: (id) => byId.get(id) || null,
    querySelectorAll: (selector) => {
      const [parent, child] = selector.split(/\s+/);
      return [...root.descendants()].filter(
        (n) => n.tagName === child.toUpperCase() &&
          n.parentNode && n.parentNode.tagName === parent.toUpperCase()
      );
    },
    addEventListener: () => {},
  };
  for (const node of root.descendants()) node.ownerDocument = doc;
  return doc;
}

/* --------------------------------------------------------------- helpers */

function textOf(node) {
  return node ? node.textContent : "";
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(fn, timeout = 15000, label = "condition") {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (fn()) return true;
    await sleep(50);
  }
  throw new Error(`timeout waiting for ${label}`);
}

function serialize(node, depth = 0) {
  const pad = "  ".repeat(depth);
  if (node.tagName === "#text") return pad + node._text.trim();
  const attrs = Object.entries(node.attributes || {})
    .map(([k, v]) => `${k}="${v}"`).join(" ");
  const open = `<${node.tagName.toLowerCase()}${attrs ? " " + attrs : ""}>`;
  if (!node.children.length) {
    const text = (node._text || "").trim();
    return pad + open + (text ? escapeHtml(text) : "") +
      `</${node.tagName.toLowerCase()}>`;
  }
  const inner = node.children.map((c) => serialize(c, depth + 1)).filter(Boolean).join("\n");
  return `${pad}${open}\n${inner}\n${pad}</${node.tagName.toLowerCase()}>`;
}

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ------------------------------------------------------------------ main */

async function main() {
  const indexHtml = fs.readFileSync(path.join(ROOT, "vulnova/static/index.html"), "utf8");
  const appJs = fs.readFileSync(path.join(ROOT, "vulnova/static/app.js"), "utf8");

  const doc = makeDocument(indexHtml);
  const sandbox = {
    document: doc,
    window: {},
    fetch: (url) => {
      const full = url.startsWith("http") ? url : BASE + url;
      return fetch(full);
    },
    URLSearchParams,
    setTimeout,
    clearTimeout,
    encodeURIComponent,
    console,
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(appJs, sandbox, { filename: "app.js" });

  console.log(`DOM-shim render check against ${BASE}`);
  console.log("(not a screenshot — see the file header)");

  await waitFor(() => (doc.getElementById("rows") || { children: [] }).children.length > 0,
    20000, "initial ranking render");

  const bodyText = textOf(doc.body);
  const rows = doc.getElementById("rows").children;

  check("status line shows the reference date", /reference 2026-10-16/.test(bodyText), bodyText.slice(0, 120));
  check("status line shows record and ranking counts", /CVE records/.test(bodyText) && /ranked/.test(bodyText));
  check("coverage renders a 2020 chip", /2020 · 14,410 records/.test(bodyText), bodyText.match(/2020[^·]*·[^·]*/));
  check("coverage shows non-KEV counts", /non-KEV/.test(bodyText));
  check("coverage states no 2020-2023 gap", /No 2020–2023 non-KEV coverage gap/.test(bodyText));
  check("coverage shows EPSS coverage", /EPSS: 390,400 scores/.test(bodyText));
  check("ranking rendered 25 rows", rows.length === 25, rows.length);
  check("header has nine columns",
    doc.getElementById("ranking").children[0].children[0].children.length === 9);
  check("first row shows a P1 band chip", /P1_CRITICAL/.test(textOf(rows[0])));
  check("KEV members carry a KEV chip", /KEV/.test(textOf(rows[0])));

  // ---- DEF-2: the asterisk marker and its legend
  const legendNode = doc.getElementById("ranking-legend");
  check("DEF-2 legend element exists", !!legendNode);
  check("DEF-2 no asterisk on a row without insufficient evidence",
    !/\*/.test(textOf(rows[0])), textOf(rows[0]));
  check("DEF-2 legend is hidden when no insufficient row is visible",
    /is-empty/.test(legendNode.className) && textOf(legendNode) === "",
    `${legendNode.className} / ${textOf(legendNode)}`);

  const firstId = rows[0].getAttribute("data-cve");
  const api = await (await fetch(`${BASE}/api/ranking?limit=1`)).json();
  check("rendered score matches API", textOf(rows[0]).includes(String(api.rows[0].score)), firstId);

  // ---- conflict detail
  const conflictId = "CVE-2026-41940";
  await sandbox.window.__vulnova.loadDetail(conflictId);
  const detailText = textOf(doc.getElementById("detail"));
  check("detail shows the CVE", detailText.includes(conflictId));
  check("detail lists both conflicting values",
    detailText.includes("9.3") && detailText.includes("9.8"));
  check("detail marks the selected value", /SELECTED/.test(detailText));
  check("detail explains non-comparability", /NOT directly comparable/.test(detailText));
  check("detail shows the selection rule", /highest CVSS version wins/.test(detailText));
  check("DEF-3 heading counts observed values",
    /CVSS evidence \u2014 2 observed values/.test(detailText), detailText.slice(0, 200));
  check("detail renders the score breakdown", /Score breakdown/.test(detailText));
  check("detail renders provenance timestamps", /2026-10-17T/.test(detailText));
  check("detail names publication_recency in the breakdown", /publication_recency/.test(detailText));
  check("detail headings distinguish publication from exploitation recency",
    /Publication recency \(not exploitation recency\)/.test(detailText));
  check("detail states the component is publication-date based",
    /measures the CVE publication date only/.test(detailText));
  check("detail lists what publication_recency does not represent",
    /publication_recency does NOT represent: recent exploitation activity; recent KEV inclusion; an independently verified increase in threat activity\./.test(detailText));

  // ---- DEF-1: equal values, different CVSS versions must still warn
  const equalCrossId = "CVE-2015-3306";
  await sandbox.window.__vulnova.loadDetail(equalCrossId);
  const equalCrossText = textOf(doc.getElementById("detail"));
  const equalPayload = await (await fetch(`${BASE}/api/cve/${equalCrossId}`)).json();
  check("DEF-1 precondition: has_conflict is false",
    equalPayload.observed.cvss.conflict.has_conflict === false,
    String(equalPayload.observed.cvss.conflict.has_conflict));
  check("DEF-1 precondition: comparable is false",
    equalPayload.observed.cvss.conflict.comparable === false,
    String(equalPayload.observed.cvss.conflict.comparable));
  check("DEF-1 equal values across versions still warn",
    /NOT directly comparable/.test(equalCrossText), equalCrossText.slice(0, 300));
  check("DEF-1 equal values are not called directly comparable",
    /agree/.test(equalCrossText) && /NOT directly comparable/.test(equalCrossText));

  // ---- equal values, same CVSS version: comparable, no false warning
  const equalSameId = "CVE-2021-23203";
  await sandbox.window.__vulnova.loadDetail(equalSameId);
  const equalSameText = textOf(doc.getElementById("detail"));
  const equalSamePayload = await (await fetch(`${BASE}/api/cve/${equalSameId}`)).json();
  check("same-version precondition: comparable is true",
    equalSamePayload.observed.cvss.conflict.comparable === true,
    String(equalSamePayload.observed.cvss.conflict.comparable));
  check("same-version case shows the same-scale rationale",
    /share a scale/.test(equalSameText), equalSameText.slice(0, 300));
  check("same-version case raises no false non-comparability warning",
    !/NOT directly comparable/.test(equalSameText), equalSameText.slice(0, 300));
  check("same-version heading counts observed values",
    /CVSS evidence \u2014 2 observed values/.test(equalSameText));

  // ---- insufficient-evidence detail
  const weak = await (await fetch(`${BASE}/api/ranking?review=1&limit=1`)).json();
  const weakId = "CVE-2025-52097";
  await sandbox.window.__vulnova.loadDetail(weakId);
  const weakText = textOf(doc.getElementById("detail"));
  check("insufficient detail shows the warning banner",
    /Insufficient evidence — review required/.test(weakText));
  check("insufficient detail keeps the numeric band",
    weakText.includes("P4_LOW"));
  check("insufficient detail labels the header band",
    /P4_LOW \(INSUFFICIENT EVIDENCE\)/.test(weakText));
  check("insufficient detail states it is not a low-risk judgement",
    /NOT an assessment that this vulnerability is low risk/.test(weakText));
  check("insufficient detail lists missing signals", /MISSING: cvss_severity/.test(weakText));
  check("DEF-3 heading reports zero observed values",
    /CVSS evidence \u2014 0 observed values \u00b7 1 source reports none/.test(weakText),
    weakText.slice(0, 300));
  check("DEF-3 heading does not claim a source value exists",
    !/\(1 source values\)/.test(weakText), weakText.slice(0, 300));

  // ---- DEF-5: missing CVSS version and human-readable status labels
  const weakPayload = await (await fetch(`${BASE}/api/cve/${weakId}`)).json();
  const weakCandidate = weakPayload.observed.cvss.candidates[0];
  check("DEF-5 missing version is not rendered as v?",
    !/v\?/.test(weakText), weakText.slice(0, 300));
  check("DEF-5 missing version is labelled explicitly",
    /Version not stated/.test(weakText), weakText.slice(0, 400));
  check("DEF-5 missing version is never rendered as a version number",
    !/v0(?!\.)/.test(weakText), weakText.slice(0, 400));
  check("DEF-5 raw status enum is not shown to the user",
    !/MISSING_FROM_SOURCE/.test(weakText), weakText.slice(0, 400));
  check("DEF-5 missing status reads 'Missing from source'",
    /Missing from source/.test(weakText), weakText.slice(0, 400));
  // four display sites carry MISSING_FROM_SOURCE: the epss_probability and
  // cvss_severity signal chips, the CVSS candidate chip and the EPSS status
  check("DEF-5 every missing status uses the same label",
    (weakText.match(/Missing from source/g) || []).length === 4,
    (weakText.match(/Missing from source/g) || []).length);
  check("DEF-5 API still returns the raw enum and the null version",
    weakCandidate.status === "MISSING_FROM_SOURCE" && weakCandidate.version === null,
    JSON.stringify({ status: weakCandidate.status, version: weakCandidate.version }));

  // ---- DEF-4: state and state_basis come from the source, per source
  await sandbox.window.__vulnova.loadDetail("CVE-2026-41940");
  const statedStateText = textOf(doc.getElementById("detail"));
  check("DEF-4 stated state is shown verbatim from cvelistV5",
    /StatePUBLISHED/.test(statedStateText), statedStateText.slice(-500));
  check("DEF-4 stated state carries basis 'stated'",
    /State basisstated/.test(statedStateText), statedStateText.slice(-500));
  check("DEF-4 detail names the primary source",
    /Primary sourcecvelistv5/.test(statedStateText));

  await sandbox.window.__vulnova.loadDetail("CVE-1999-0001");
  const absentStateText = textOf(doc.getElementById("detail"));
  check("DEF-4 absent state is rendered as not stated",
    /Statenot stated by the source/.test(absentStateText), absentStateText.slice(-500));
  check("DEF-4 absent state carries basis 'not_stated'",
    /State basisnot_stated/.test(absentStateText), absentStateText.slice(-500));
  check("DEF-4 detail does not invent a state",
    !/StatePUBLISHED/.test(absentStateText));

  await sandbox.window.__vulnova.loadDetail("CVE-2007-3010");
  const dualStateText = textOf(doc.getElementById("detail"));
  check("DEF-4 alternate source keeps its own state, basis and timestamp",
    /Alternate source legacy_cve_csv: state not stated \(basis not_stated, retrieved 2026-10-17T/.test(dualStateText),
    dualStateText.slice(-600));

  // ---- DEF-5: known versions and observed status keep their real labels
  await sandbox.window.__vulnova.loadDetail("CVE-2021-23203");
  const knownVersionText = textOf(doc.getElementById("detail"));
  check("DEF-5 known versions still render as v3.1",
    (knownVersionText.match(/v3\.1/g) || []).length >= 2,
    (knownVersionText.match(/v3\.1/g) || []).length);
  check("DEF-5 known versions do not fall back to the missing label",
    !/Version not stated/.test(knownVersionText));
  check("DEF-5 observed status reads 'Observed'",
    /Observed/.test(knownVersionText));
  check("DEF-5 raw OBSERVED enum is not shown to the user",
    !/\bOBSERVED\b/.test(knownVersionText), knownVersionText.slice(0, 400));
  check("DEF-5 KEV status reads 'Not listed in catalog'",
    /Not listed in catalog/.test(knownVersionText));
  check("DEF-5 raw KEV enum is not shown to the user",
    !/NOT_LISTED_IN_CATALOG/.test(knownVersionText));

  // ---- filters
  const reviewBox = doc.getElementById("review");
  reviewBox.checked = true;
  reviewBox.listeners.change[0]({ target: reviewBox });
  await sleep(600);
  const reviewRows = doc.getElementById("rows").children;
  check("review filter renders only insufficient rows",
    reviewRows.length > 0 && reviewRows.every((r) => /INSUFFICIENT EVIDENCE/.test(textOf(r))),
    reviewRows.length);
  check("DEF-2 insufficient rows are marked with an asterisk",
    reviewRows.every((r) => textOf(r).includes("*")), reviewRows.length);
  check("DEF-2 the asterisk is explained by a visible legend",
    /INSUFFICIENT EVIDENCE/.test(textOf(legendNode)) &&
    /not an assessment that the vulnerability is low risk/.test(textOf(legendNode)) &&
    !/is-empty/.test(legendNode.className), textOf(legendNode));
  check("DEF-2 legend refers to the marker and the page count",
    /^\* \d+ rows? on this page (has|have) INSUFFICIENT EVIDENCE/.test(textOf(legendNode)),
    textOf(legendNode));

  reviewBox.checked = false;
  reviewBox.listeners.change[0]({ target: reviewBox });
  const kevBox = doc.getElementById("kev");
  kevBox.checked = true;
  kevBox.listeners.change[0]({ target: kevBox });
  await sleep(600);
  const kevRows = doc.getElementById("rows").children;
  check("KEV filter renders only KEV rows",
    kevRows.length > 0 && kevRows.every((r) => /KEV/.test(textOf(r))), kevRows.length);

  kevBox.checked = false;
  kevBox.listeners.change[0]({ target: kevBox });
  await sleep(600);
  check("clearing the filter restores 25 rows", doc.getElementById("rows").children.length === 25);
  check("DEF-2 legend clears when no insufficient row is shown",
    /is-empty/.test(legendNode.className) && textOf(legendNode) === "",
    `${legendNode.className} / ${textOf(legendNode)}`);

  // ---- dump
  if (DUMP) {
    fs.mkdirSync(DUMP, { recursive: true });
    fs.writeFileSync(path.join(DUMP, "00_README.txt"), [
      "DOM-SHIM RENDER OUTPUT — NOT A SCREENSHOT.",
      "",
      "Produced by tools/ui_render_check.js, which parses index.html into a",
      "minimal DOM and executes the real static/app.js. No browser was used.",
      "These files show the text the application generates; they say nothing",
      "about visual layout, CSS or accessibility.",
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(DUMP, "01_list.html"), serialize(doc.getElementById("ranking").parentNode));
    await sandbox.window.__vulnova.loadDetail(conflictId);
    fs.writeFileSync(path.join(DUMP, "02_detail_conflict.html"), serialize(doc.getElementById("detail")));
    await sandbox.window.__vulnova.loadDetail(weakId);
    fs.writeFileSync(path.join(DUMP, "03_detail_insufficient.html"), serialize(doc.getElementById("detail")));
    fs.writeFileSync(path.join(DUMP, "04_coverage.txt"), textOf(doc.getElementById("coverage")));
    await sandbox.window.__vulnova.loadDetail(equalCrossId);
    fs.writeFileSync(path.join(DUMP, "05_detail_equal_values_cross_version.html"),
      serialize(doc.getElementById("detail")));
    await sandbox.window.__vulnova.loadDetail(equalSameId);
    fs.writeFileSync(path.join(DUMP, "06_detail_equal_values_same_version.html"),
      serialize(doc.getElementById("detail")));
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length} PASS, ${failed.length} FAIL`);
  if (failed.length) {
    failed.forEach((f) => console.log(`  FAILED: ${f.name} ${f.detail}`));
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("render check crashed:", error);
  process.exit(2);
});
