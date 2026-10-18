#!/usr/bin/env node
/*
 * RANKING REQUEST-ORDER REGRESSION CHECK (DEF-7).
 *
 * A DOM-shim harness — NOT a screenshot. It parses index.html into a
 * minimal DOM, executes the real static/app.js, and replaces fetch
 * with a mock whose /api/ranking responses stay pending until the
 * test releases them. That makes the overlapping-request race
 * deterministic: no real network and no timing-dependent sleeps are
 * involved in producing the race (the only timer is the app's own
 * 180 ms search debounce, which is awaited by condition polling).
 *
 * Scenarios:
 *   1. normal search renders its result
 *   2. search A pending, search B issued, B resolved first, then A —
 *      A must not overwrite B's rows, count or pagination
 *   3. pagination still works (next page request renders page 2)
 *   4. review-filter request pending, Reset clicked, reset response
 *      resolved first, then the stale filtered response — it must not
 *      overwrite the reset view or resurrect the legend
 */

const fs = require("fs");
const path = require("path");
const vm = require("vm");

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
  }
  get textContent() {
    return this._text;
  }
}

/* --------------------------------------------------------------- parsing */

const VOID = new Set(["br", "hr", "img", "input", "meta", "link", "source"]);
const ATTR_RE = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*"([^"]*)"|\s*=\s*'([^']*)')?/g;

function parseHTML(html) {
  const root = new Node("#root");
  root.ownerDocument = null;
  let current = root;
  let i = 0;
  while (i < html.length) {
    if (html[i] === "<") {
      if (html.startsWith("<!--", i)) {
        const end = html.indexOf("-->", i);
        i = end === -1 ? html.length : end + 3;
        continue;
      }
      if (html[i + 1] === "/") {
        const gt = html.indexOf(">", i);
        i = gt + 1;
        if (current.parentNode) current = current.parentNode;
        continue;
      }
      const gt = html.indexOf(">", i);
      if (gt === -1) break;
      const raw = html.slice(i + 1, gt).trim();
      i = gt + 1;
      if (raw.startsWith("!")) continue;
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
      continue;
    }
    const next = html.indexOf("<", i);
    const text = html.slice(i, next === -1 ? html.length : next);
    i = next === -1 ? html.length : next;
    if (text.trim()) current.appendChild(new TextNode(text));
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

/* Flush all pending promise microtasks deterministically. */
async function drain() {
  await sleep(0);
  await sleep(0);
}

/* ------------------------------------------------------------------ main */

async function main() {
  const indexHtml = fs.readFileSync(path.join(ROOT, "vulnova/static/index.html"), "utf8");
  const appJs = fs.readFileSync(path.join(ROOT, "vulnova/static/app.js"), "utf8");
  const doc = makeDocument(indexHtml);

  /* ---- mock fetch: /api/status resolves at once, every /api/ranking
   * call is captured and stays pending until the test releases it ---- */
  const rankingRequests = [];
  const STATUS = {
    reference_date: "2026-10-16",
    counts: { cve_record: 348670, ranking: 345249 },
    ranking: { built_at: "2026-10-18T00:00:00Z" },
    coverage: {
      published_year_totals: [
        { year: "2020", records: 21081, kev_listed: 100 },
        { year: "2026", records: 75326, kev_listed: 200 }
      ],
      windows: [],
      gaps: [],
      epss: { total: 390400, coverage_of_store: 86.42, unmatched_records: 45474 }
    }
  };
  const jsonResponse = (body) => ({ ok: true, status: 200, json: () => Promise.resolve(body) });
  const row = (cveId, opts) => {
    const o = opts || {};
    return {
      cve_id: cveId,
      score: o.score === undefined ? 50 : o.score,
      band: o.band || "P3_MODERATE",
      kev_listed: false,
      cvss_value: 7.5,
      cvss_version: "3.1",
      cvss_source: "cvelistv5",
      cvss_candidates: 1,
      cvss_conflict: false,
      epss_probability: 0.5,
      published: "2026-01-01",
      review_required: !!o.review_required,
      evidence_status: o.review_required ? "INSUFFICIENT_EVIDENCE" : "SUFFICIENT_EVIDENCE"
    };
  };
  const payload = (rows, total, offset) => ({
    total: total, limit: 25, offset: offset || 0, rows: rows
  });

  const pageA = Array.from({ length: 25 }, (_, i) => row("CVE-2026-" + (10000 + i)));
  const pageB = Array.from({ length: 25 }, (_, i) => row("CVE-2025-" + (10000 + i)));

  const sandbox = {
    document: doc,
    window: {},
    fetch: (url) => {
      const u = String(url);
      if (u.indexOf("/api/status") === 0) return Promise.resolve(jsonResponse(STATUS));
      if (u.indexOf("/api/ranking") === 0) {
        let release;
        const pending = new Promise((resolve) => { release = resolve; });
        rankingRequests.push({
          url: u,
          release: (body) => release(jsonResponse(body))
        });
        return pending;
      }
      return Promise.resolve(jsonResponse({}));
    },
    URLSearchParams, setTimeout, clearTimeout, encodeURIComponent, console,
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(appJs, sandbox, { filename: "app.js" });

  console.log("ranking request-order regression check (DEF-7) — mocked fetch, no network");

  const rows = () => [...doc.getElementById("rows").children];
  const rowIds = () => rows().map((r) => r.getAttribute("data-cve"));
  const meta = () => doc.getElementById("list-meta").textContent;
  const pageIndicator = () => doc.getElementById("page").textContent;
  const legend = () => doc.getElementById("ranking-legend");
  const q = doc.getElementById("q");

  /* ---- boot: the initial request renders the default first page ---- */
  await waitFor(() => rankingRequests.length >= 1, 10000, "boot ranking request");
  check("boot issues exactly one ranking request", rankingRequests.length === 1, rankingRequests.length);
  rankingRequests[0].release(payload(pageA, 345249));
  await waitFor(() => rows().length === 25, 10000, "default page renders");
  check("default page renders 25 rows", rows().length === 25, rows().length);
  check("default meta shows the full total", /345,249 matching CVEs/.test(meta()), meta());
  check("default pagination shows page 1", pageIndicator() === "1 / 13810", pageIndicator());

  /* ---- pagination still works ---- */
  doc.getElementById("next").listeners.click[0]({ target: doc.getElementById("next") });
  await waitFor(() => rankingRequests.length === 2, 10000, "page-2 request");
  check("pagination requests offset 25", rankingRequests[1].url.includes("offset=25"), rankingRequests[1].url);
  rankingRequests[1].release(payload(pageB, 345249, 25));
  await waitFor(() => rowIds()[0] === "CVE-2025-10000", 10000, "page 2 renders");
  check("page 2 renders its own rows", rowIds()[0] === "CVE-2025-10000", rowIds()[0]);
  check("pagination indicator shows page 2", pageIndicator() === "2 / 13810", pageIndicator());

  /* ---- normal successful search ---- */
  q.value = "CVE-2021-23203";
  q.listeners.input[0]({ target: q });
  await waitFor(() => rankingRequests.length === 3, 10000, "search request after debounce");
  check("search requests the typed query", rankingRequests[2].url.includes("q=CVE-2021-23203"), rankingRequests[2].url);
  rankingRequests[2].release(payload([row("CVE-2021-23203", { score: 18, band: "P4_LOW" })], 1));
  await waitFor(() => rowIds().length === 1 && rowIds()[0] === "CVE-2021-23203", 10000, "search renders");
  check("normal search renders its single result", rowIds()[0] === "CVE-2021-23203", rowIds().join(","));
  check("search meta shows 1 matching CVE", /1 matching CVEs/.test(meta()), meta());

  /* ---- DEF-7 core: overlapping searches, B resolved before A ---- */
  q.value = "CVE-2025-52097";
  q.listeners.input[0]({ target: q });
  await waitFor(() => rankingRequests.length === 4, 10000, "search A request");
  const requestA = rankingRequests[3];
  check("search A requested the typed query", requestA.url.includes("q=CVE-2025-52097"), requestA.url);

  q.value = "CVE-2026-41940";
  q.listeners.input[0]({ target: q });
  await waitFor(() => rankingRequests.length === 5, 10000, "search B request");
  const requestB = rankingRequests[4];
  check("search B requested the typed query", requestB.url.includes("q=CVE-2026-41940"), requestB.url);

  // B returns first and must render
  requestB.release(payload([row("CVE-2026-41940", { score: 98, band: "P1_CRITICAL" })], 1));
  await waitFor(() => rowIds().length === 1 && rowIds()[0] === "CVE-2026-41940", 10000, "B renders first");
  check("newer search B renders its own row", rowIds()[0] === "CVE-2026-41940", rowIds().join(","));
  check("meta corresponds to B", /1 matching CVEs/.test(meta()), meta());
  check("pagination corresponds to B", pageIndicator() === "1 / 1", pageIndicator());

  // A returns afterwards and must NOT overwrite B
  requestA.release(payload([row("CVE-2025-52097", { score: 10, band: "P4_LOW", review_required: true })], 1));
  await drain();
  check("stale search A does not overwrite B's rows",
    rowIds().length === 1 && rowIds()[0] === "CVE-2026-41940", rowIds().join(","));
  check("stale search A does not render its own row",
    !rowIds().includes("CVE-2025-52097"), rowIds().join(","));
  check("stale search A does not overwrite B's count", /1 matching CVEs/.test(meta()), meta());
  check("stale search A does not overwrite B's pagination", pageIndicator() === "1 / 1", pageIndicator());
  check("stale search A does not resurrect a legend",
    legend().className.includes("is-empty") && legend().textContent === "", legend().textContent.slice(0, 80));

  /* ---- DEF-7 reproduction from the live browser: filter, then Reset ---- */
  const reviewBox = doc.getElementById("review");
  reviewBox.checked = true;
  reviewBox.listeners.change[0]({ target: reviewBox });
  await waitFor(() => rankingRequests.length === 6, 10000, "review-filter request");
  const requestReview = rankingRequests[5];
  check("review filter requested the filtered view", requestReview.url.includes("review=1"), requestReview.url);

  doc.getElementById("reset").listeners.click[0]({ target: doc.getElementById("reset") });
  await waitFor(() => rankingRequests.length === 7, 10000, "reset request");
  const requestReset = rankingRequests[6];
  check("reset requested the unfiltered view", !requestReset.url.includes("review="), requestReset.url);

  // reset's response arrives first and renders
  requestReset.release(payload(pageA, 345249));
  await waitFor(() => rows().length === 25 && rowIds()[0] === "CVE-2026-10000", 10000, "reset renders");
  check("reset restores the default rows", rowIds()[0] === "CVE-2026-10000", rowIds()[0]);
  check("reset restores the default count", /345,249 matching CVEs/.test(meta()), meta());

  // the stale filtered response arrives afterwards and must not win
  requestReview.release(payload([row("CVE-2025-52097", { review_required: true })], 1));
  await drain();
  check("stale filtered response does not overwrite the reset view",
    rows().length === 25 && rowIds()[0] === "CVE-2026-10000", rowIds()[0]);
  check("stale filtered response keeps the default count", /345,249 matching CVEs/.test(meta()), meta());
  check("stale filtered response does not resurrect the legend",
    legend().className.includes("is-empty") && legend().textContent === "", legend().textContent.slice(0, 80));

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length} PASS, ${failed.length} FAIL`);
  if (failed.length) {
    failed.forEach((f) => console.log(`  FAILED: ${f.name} ${f.detail}`));
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error("RACE_CHECK_ERROR", error);
  process.exitCode = 1;
});
