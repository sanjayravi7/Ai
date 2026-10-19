#!/usr/bin/env node
/*
 * RANKING REQUEST-ORDER REGRESSION CHECK (DEF-7).
 *
 * A DOM-shim harness — NOT a screenshot. It parses index.html into a
 * minimal DOM, executes the real static/app.js, and replaces fetch
 * with a mock whose /api/ranking responses stay pending until the
 * test releases them. That makes the overlapping-request race
 * deterministic: no real network. Search debounce timers are explicitly
 * advanced; request promises are manually released. Also checks the 1.3
 * loading, failure, payload-validation and Retry states.
 *
 * Scenarios:
 *   1. normal search renders its result
 *   2. search A pending, search B issued, B resolved first, then A —
 *      A must not overwrite B's rows, count or pagination
 *   3. reverse completion order: A resolves first while B is
 *      already pending — A is superseded and ignored, B renders
 *   4. a newer empty result set must not be overwritten by an
 *      older response that carries rows
 *   5. an older request failure must not disturb newer results
 *   6. pagination still works (next page request renders page 2)
 *   7. review-filter request pending, Reset clicked, reset response
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
  await new Promise((resolve) => setImmediate(resolve));
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

  const searchTimers = new Map();
  let timerId = 0;
  function flushSearchTimers() {
    const timers = [...searchTimers.values()];
    searchTimers.clear();
    timers.forEach((fn) => fn());
  }

  const sandbox = {
    document: doc,
    window: {},
    fetch: (url) => {
      const u = String(url);
      if (u.indexOf("/api/status") === 0) return Promise.resolve(jsonResponse(STATUS));
      if (u.indexOf("/api/ranking") === 0) {
        let release;
        let reject;
        const pending = new Promise((resolve, rejectFn) => {
          release = resolve;
          reject = rejectFn;
        });
        rankingRequests.push({
          url: u,
          release: (body) => release(jsonResponse(body)),
          releaseError: (error) => reject(error),
          releaseHTTP: (status, body) => release({ ok: false, status, json: () => Promise.resolve(body) }),
          releaseInvalidJSON: () => release({ ok: true, status: 200,
            json: () => Promise.reject(new SyntaxError("private parse details")) })
        });
        return pending;
      }
      return Promise.resolve(jsonResponse({}));
    },
    URLSearchParams, encodeURIComponent, console,
    setTimeout: (fn, ms) => {
      if (ms !== 180) throw new Error("Unexpected application timer: " + ms);
      const id = ++timerId; searchTimers.set(id, fn); return id;
    },
    clearTimeout: (id) => searchTimers.delete(id),
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(appJs, sandbox, { filename: "app.js" });

  console.log("ranking request-order regression check (DEF-7) — mocked fetch, no network");

  // Normal and stale failures must never leak an unhandled rejection.
  const rejections = [];
  process.on("unhandledRejection", (reason) => {
    rejections.push(String((reason && reason.message) || reason));
  });

  const rows = () => [...doc.getElementById("rows").children];
  const rowIds = () => rows().map((r) => r.getAttribute("data-cve"));
  const meta = () => doc.getElementById("list-meta").textContent;
  const pageIndicator = () => doc.getElementById("page").textContent;
  const legend = () => doc.getElementById("ranking-legend");
  const q = doc.getElementById("q");

  /* ---- boot: the initial request renders the default first page ---- */
  await waitFor(() => rankingRequests.length >= 1, 10000, "boot ranking request");
  check("boot issues exactly one ranking request", rankingRequests.length === 1, rankingRequests.length);
  check("initial loading is visible while request is pending", !doc.getElementById("ranking-loading").hidden);
  check("loading has a polite live status", doc.getElementById("ranking-loading").getAttribute("role") === "status" &&
    doc.getElementById("ranking-loading").getAttribute("aria-live") === "polite");
  check("ranking table is busy during loading", doc.getElementById("ranking").getAttribute("aria-busy") === "true");
  rankingRequests[0].release(payload(pageA, 345249));
  await waitFor(() => rows().length === 25, 10000, "default page renders");
  check("success clears loading and busy state", doc.getElementById("ranking-loading").hidden &&
    doc.getElementById("ranking").getAttribute("aria-busy") === "false");
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
  flushSearchTimers();
  await waitFor(() => rankingRequests.length === 3, 10000, "search request after debounce");
  check("search requests the typed query", rankingRequests[2].url.includes("q=CVE-2021-23203"), rankingRequests[2].url);
  rankingRequests[2].release(payload([row("CVE-2021-23203", { score: 18, band: "P4_LOW" })], 1));
  await waitFor(() => rowIds().length === 1 && rowIds()[0] === "CVE-2021-23203", 10000, "search renders");
  check("normal search renders its single result", rowIds()[0] === "CVE-2021-23203", rowIds().join(","));
  check("search meta shows 1 matching CVE", /1 matching CVEs/.test(meta()), meta());

  /* ---- DEF-7 core: overlapping searches, B resolved before A ---- */
  q.value = "CVE-2025-52097";
  q.listeners.input[0]({ target: q });
  flushSearchTimers();
  await waitFor(() => rankingRequests.length === 4, 10000, "search A request");
  const requestA = rankingRequests[3];
  check("search A requested the typed query", requestA.url.includes("q=CVE-2025-52097"), requestA.url);

  q.value = "CVE-2026-41940";
  q.listeners.input[0]({ target: q });
  flushSearchTimers();
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

  /* ---- reverse completion order: the older response resolves
   * first, while the newer request is already pending ---- */
  const beforeC = rankingRequests.length;
  q.value = "CVE-2021-23203";
  q.listeners.input[0]({ target: q });
  flushSearchTimers();
  await waitFor(() => rankingRequests.length === beforeC + 1, 10000, "search C request");
  const requestC = rankingRequests[beforeC];
  check("search C requested the typed query", requestC.url.includes("q=CVE-2021-23203"), requestC.url);

  q.value = "CVE-2025-52097";
  q.listeners.input[0]({ target: q });
  flushSearchTimers();
  await waitFor(() => rankingRequests.length === beforeC + 2, 10000, "search D request");
  const requestD = rankingRequests[beforeC + 1];
  check("search D requested the typed query", requestD.url.includes("q=CVE-2025-52097"), requestD.url);

  // C resolves first but D already superseded it: C must be
  // ignored and the view must remain exactly as it was
  // (search B's single result) until D arrives
  requestC.release(payload([row("CVE-2021-23203", { score: 18, band: "P4_LOW" })], 1));
  await drain();
  check("in-order older response is ignored while a newer request is pending",
    rowIds().length === 1 && rowIds()[0] === "CVE-2026-41940" &&
    /1 matching CVEs/.test(meta()), rowIds()[0] + " / " + meta());

  check("older success cannot clear newer loading", !doc.getElementById("ranking-loading").hidden);

  // D resolves afterwards and must render
  requestD.release(payload([row("CVE-2025-52097", { score: 10, band: "P4_LOW", review_required: true })], 1));
  await waitFor(() => rowIds().length === 1 && rowIds()[0] === "CVE-2025-52097", 10000, "D renders");
  check("newer search D renders after the older response",
    rowIds()[0] === "CVE-2025-52097", rowIds().join(","));
  check("legend corresponds to D",
    !legend().className.includes("is-empty") && /\* 1 row on this page has/.test(legend().textContent),
    legend().textContent.slice(0, 60));

  /* ---- a newer empty result set must not be overwritten by an
   * older response that carries rows ---- */
  const beforeE = rankingRequests.length;
  q.value = "no-such-cve-xyz";
  q.listeners.input[0]({ target: q });
  flushSearchTimers();
  await waitFor(() => rankingRequests.length === beforeE + 1, 10000, "search E request");
  const requestE = rankingRequests[beforeE];

  q.value = "CVE-2026-41940";
  q.listeners.input[0]({ target: q });
  flushSearchTimers();
  await waitFor(() => rankingRequests.length === beforeE + 2, 10000, "search F request");
  const requestF = rankingRequests[beforeE + 1];

  // F (newer) resolves first with an empty result set
  requestF.release(payload([], 0));
  await waitFor(() => rows().length === 1 &&
    /No CVE matches the current filters/.test(textOf(doc.getElementById("rows"))),
    10000, "empty state renders");
  check("newer empty search renders the empty state",
    /No CVE matches the current filters/.test(textOf(doc.getElementById("rows"))),
    textOf(doc.getElementById("rows")).slice(0, 80));
  check("empty state keeps the zero count", /0 matching CVEs/.test(meta()), meta());
  check("empty state hides the legend", legend().className.includes("is-empty"), legend().className);

  // E (older, carrying rows) resolves afterwards: must not resurrect rows
  requestE.release(payload([row("CVE-2026-41940", { score: 98, band: "P1_CRITICAL" })], 1));
  await drain();
  check("stale response does not resurrect rows over the newer empty state",
    rows().length === 1 && /No CVE matches the current filters/.test(textOf(doc.getElementById("rows"))),
    textOf(doc.getElementById("rows")).slice(0, 80));

  /* ---- an older request failure must not disturb newer results ---- */
  const beforeG = rankingRequests.length;
  q.value = "CVE-2026-41940";
  q.listeners.input[0]({ target: q });
  flushSearchTimers();
  await waitFor(() => rankingRequests.length === beforeG + 1, 10000, "search G request");
  const requestG = rankingRequests[beforeG];

  q.value = "CVE-2015-3306";
  q.listeners.input[0]({ target: q });
  flushSearchTimers();
  await waitFor(() => rankingRequests.length === beforeG + 2, 10000, "search H request");
  const requestH = rankingRequests[beforeG + 1];

  requestH.release(payload(
    [row("CVE-2015-3306", { score: 90, band: "P1_CRITICAL" }),
     row("CVE-2015-3307", { score: 89, band: "P1_CRITICAL" })], 2));
  await waitFor(() => rowIds().length === 2 && rowIds()[0] === "CVE-2015-3306", 10000, "H renders");
  check("newer search H renders its rows", rowIds()[0] === "CVE-2015-3306", rowIds().join(","));

  // The older G failure must neither alter rows nor surface an error.
  requestG.releaseError(new Error("simulated network failure"));
  await drain();
  check("stale failed request does not alter the newer results",
    rowIds().length === 2 && rowIds()[0] === "CVE-2015-3306", rowIds().join(","));
  check("stale failure is handled without an unhandled rejection or error UI",
    rejections.length === 0 && doc.getElementById("ranking-error").hidden,
    rejections.join(" | "));

  /* ---- DEF-7 reproduction from the live browser: filter, then Reset ---- */
  const beforeR = rankingRequests.length;
  const reviewBox = doc.getElementById("review");
  reviewBox.checked = true;
  reviewBox.listeners.change[0]({ target: reviewBox });
  await waitFor(() => rankingRequests.length === beforeR + 1, 10000, "review-filter request");
  const requestReview = rankingRequests[beforeR];
  check("review filter requested the filtered view", requestReview.url.includes("review=1"), requestReview.url);

  doc.getElementById("reset").listeners.click[0]({ target: doc.getElementById("reset") });
  await waitFor(() => rankingRequests.length === beforeR + 2, 10000, "reset request");
  const requestReset = rankingRequests[beforeR + 1];
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

  /* ---- VULNOVA 1.3 request-state and Retry regression coverage ---- */
  const loading = () => doc.getElementById("ranking-loading");
  const errorBox = () => doc.getElementById("ranking-error");
  const retry = doc.getElementById("retry-ranking");
  const band = doc.getElementById("band");
  const kev = doc.getElementById("kev");
  const click = (node) => node.listeners.click[0]({ target: node });
  const change = (node) => node.listeners.change[0]({ target: node });
  const begin = () => {
    const before = rankingRequests.length;
    sandbox.__vulnova.loadRanking();
    if (rankingRequests.length !== before + 1) throw new Error("request not issued");
    return rankingRequests[before];
  };
  const isError = () => !errorBox().hidden && loading().hidden;
  const noEmpty = () => !/No CVE matches/.test(textOf(doc.getElementById("rows")));

  // A failed refresh removes old results/counts/legend and is not an empty success.
  const failedRefresh = begin();
  check("refresh labels retained results as previous", /Previous results shown/.test(loading().textContent));
  check("pending refresh disables paging", doc.getElementById("prev").disabled && doc.getElementById("next").disabled);
  failedRefresh.releaseError(new Error("private network stack trace"));
  await drain();
  check("network failure displays actionable error and Retry", isError() && /Check your connection and try again/.test(textOf(errorBox())) && textOf(retry) === "Retry");
  check("error message has alert semantics", [...errorBox().descendants()].some((n) => n.getAttribute && n.getAttribute("role") === "alert"));
  check("network failure is not an empty success", noEmpty() && rows().length === 0 && meta() === "Results unavailable");
  check("failure clears old rows, page and legend", rowIds().length === 0 && pageIndicator() === "–" && legend().textContent === "" && legend().className.includes("is-empty"));
  check("failure clears cached rows", sandbox.__vulnova.state.lastRows.length === 0);
  check("failure never exposes internal exception", !/private|stack trace/.test(textOf(errorBox())));

  // Set all controls, leaving a search debounce pending: Retry must use current
  // state and cancel that timer without resetting any control or adding a request.
  band.value = "P4_LOW"; change(band);
  const pendingBand = rankingRequests[rankingRequests.length - 1];
  kev.checked = true; change(kev);
  const pendingKev = rankingRequests[rankingRequests.length - 1];
  reviewBox.checked = true; change(reviewBox);
  rankingRequests[rankingRequests.length - 1].releaseError(new Error("filtered failure"));
  await drain();
  q.value = "CVE-2025-52097";
  q.listeners.input[0]({ target: q });
  const beforeRetry = rankingRequests.length;
  check("search remains debounced before Retry", searchTimers.size === 1 && rankingRequests.length === beforeRetry);
  click(retry);
  const retryRequest = rankingRequests[beforeRetry];
  check("Retry issues one new request and cancels pending debounce", rankingRequests.length === beforeRetry + 1 && searchTimers.size === 0);
  const retryParams = new URL(retryRequest.url, "http://test").searchParams;
  check("Retry preserves current query and every filter", retryParams.get("q") === q.value && retryParams.get("band") === band.value && retryParams.get("kev") === "1" && retryParams.get("review") === "1");
  check("Retry leaves search and filter controls unchanged", q.value === "CVE-2025-52097" && band.value === "P4_LOW" && kev.checked && reviewBox.checked);
  check("Retry transitions error to loading", errorBox().hidden && !loading().hidden);
  retryRequest.release(payload([row("CVE-2025-52097", { review_required: true })], 1));
  await drain();
  check("successful Retry clears error and renders latest rows", errorBox().hidden && loading().hidden && rowIds()[0] === "CVE-2025-52097");
  check("successful Retry restores evidence legend", !legend().className.includes("is-empty") && /INSUFFICIENT EVIDENCE/.test(legend().textContent));
  pendingBand.releaseError(new Error("stale band failure"));
  pendingKev.release(payload(pageA, 345249));
  await drain();
  check("rapid filter responses cannot replace retry result or legend", errorBox().hidden && rowIds()[0] === "CVE-2025-52097" && !legend().className.includes("is-empty"));

  // An empty page is only consistent when there are no remaining matches at
  // this offset. Exercise the UI, including recovery and stale-response guards.
  const inconsistentEmpty = begin();
  inconsistentEmpty.release(payload([], 1, 0));
  await drain();
  check("empty first page with positive total shows error, not empty success",
    isError() && noEmpty() && rows().length === 0 && meta() === "Results unavailable");
  check("inconsistent empty response clears pagination and evidence legend",
    pageIndicator() === "–" && legend().textContent === "" && legend().className.includes("is-empty"));

  const beforeEmptyRetry = rankingRequests.length;
  click(retry);
  check("Retry after inconsistent empty response issues a new request",
    rankingRequests.length === beforeEmptyRetry + 1 && errorBox().hidden && !loading().hidden);
  rankingRequests[beforeEmptyRetry].release(payload([row("CVE-2025-52097", { review_required: true })], 1));
  await drain();
  check("Retry after inconsistent empty response clears error and renders results",
    errorBox().hidden && loading().hidden && rowIds()[0] === "CVE-2025-52097" &&
    /1 matching CVEs/.test(meta()) && !legend().className.includes("is-empty"));

  const validEmpty = begin();
  validEmpty.release(payload([], 0, 0));
  await drain();
  check("zero total and zero offset remain a valid empty success",
    errorBox().hidden && loading().hidden && /No CVE matches/.test(textOf(doc.getElementById("rows"))) &&
    /0 matching CVEs/.test(meta()));

  for (const offset of [1, 25]) {
    const outOfRange = begin();
    outOfRange.release(payload([], 1, offset));
    await drain();
    check("empty page at offset " + offset + " with total 1 remains valid",
      errorBox().hidden && loading().hidden && /No CVE matches/.test(textOf(doc.getElementById("rows"))) &&
      /1 matching CVEs/.test(meta()) && legend().textContent === "");
  }

  const staleInvalidEmpty = begin();
  const latestNonempty = begin();
  latestNonempty.release(payload([row("CVE-2025-52097", { review_required: true })], 1));
  await drain();
  const latestView = [rowIds().join(","), meta(), pageIndicator(), legend().textContent,
    legend().className, loading().hidden, errorBox().hidden, doc.getElementById("ranking").getAttribute("aria-busy")];
  staleInvalidEmpty.release(payload([], 1, 0));
  await drain();
  check("stale inconsistent empty response cannot overwrite newer result or show error",
    JSON.stringify([rowIds().join(","), meta(), pageIndicator(), legend().textContent,
      legend().className, loading().hidden, errorBox().hidden, doc.getElementById("ranking").getAttribute("aria-busy")]) ===
    JSON.stringify(latestView) && errorBox().hidden && rowIds()[0] === "CVE-2025-52097");

  // HTTP, JSON syntax, envelope and row corruption are handled through the same
  // safe surface; none can be mistaken for zero successful matches.
  const failureCases = [
    ["HTTP 503", (r) => r.releaseHTTP(503, { message: "private server internals" })],
    ["invalid JSON", (r) => r.releaseInvalidJSON()],
    ["null payload", (r) => r.release(null)],
    ["missing rows", (r) => r.release({ total: 0, limit: 25, offset: 0 })],
    ["non-array rows", (r) => r.release({ total: 1, limit: 25, offset: 0, rows: {} })],
    ["invalid count", (r) => r.release({ ...payload([], 0), total: "0" })],
    ["invalid limit", (r) => r.release({ ...payload([], 0), limit: 0 })],
    ["invalid offset", (r) => r.release({ ...payload([], 0), offset: -1 })],
    ["inconsistent offset", (r) => r.release(payload([row("CVE-2025-52097")], 1, 25))],
    ["inconsistent count", (r) => r.release(payload([row("CVE-2025-52097")], 0))],
    ["null row", (r) => r.release(payload([null], 1))],
    ["missing row fields", (r) => r.release(payload([{ cve_id: "CVE-2025-52097" }], 1))]
  ];
  for (const [name, deliver] of failureCases) {
    const request = begin();
    deliver(request);
    await drain();
    check(name + " shows safe error, not empty success", isError() && noEmpty() && rows().length === 0 && !/private/.test(textOf(errorBox())));
  }
  const beforeFailedRetry = rankingRequests.length;
  click(retry);
  rankingRequests[beforeFailedRetry].releaseError(new Error("retry also failed"));
  await drain();
  check("failed Retry leaves understandable error with another Retry available", isError() && /Unable to load vulnerability results/.test(textOf(errorBox())));

  // Old success after new error must not replace any error-state presentation.
  const oldSuccess = begin();
  const newFailure = begin();
  newFailure.releaseError(new Error("newest fails"));
  await drain();
  oldSuccess.release(payload([row("CVE-2025-52097", { review_required: true })], 1));
  await drain();
  check("stale success cannot overwrite newer error", isError() && rows().length === 0 && meta() === "Results unavailable" && pageIndicator() === "–" && legend().textContent === "");

  const oldFailure = begin();
  const currentPending = begin();
  oldFailure.releaseError(new Error("old request fails while latest pending"));
  await drain();
  check("stale failure cannot clear latest loading or show error", !loading().hidden && errorBox().hidden && doc.getElementById("ranking").getAttribute("aria-busy") === "true");
  currentPending.release(payload([], 0));
  await drain();
  check("successful empty is distinct from loading and error", loading().hidden && errorBox().hidden && /No CVE matches/.test(textOf(doc.getElementById("rows"))) && /0 matching CVEs/.test(meta()));
  const fromEmpty = begin();
  check("loading removes prior empty message", !loading().hidden && noEmpty());
  fromEmpty.releaseError(new Error("empty refresh failed"));
  await drain();
  check("error after empty success does not retain empty message", isError() && noEmpty());

  // Reset clears every control and cancels a pending search debounce. A stale
  // response completing before Reset resolves cannot hide Reset's loading.
  q.value = "pending-reset"; q.listeners.input[0]({ target: q });
  const oldReset = begin();
  const beforeReset = rankingRequests.length;
  click(doc.getElementById("reset"));
  const resetRequest = rankingRequests[beforeReset];
  check("Reset clears all controls and debounce", q.value === "" && band.value === "" && !kev.checked && !reviewBox.checked && searchTimers.size === 0);
  check("Reset request restores default query, filters and offset", resetRequest.url === "/api/ranking?limit=25&offset=0");
  oldReset.release(payload([row("CVE-2025-52097", { review_required: true })], 1));
  await drain();
  check("stale success cannot clear Reset loading or resurrect legend", !loading().hidden && errorBox().hidden && legend().textContent === "");
  resetRequest.release(payload(pageA, 345249));
  await drain();
  check("Reset success restores defaults and clears loading/error", loading().hidden && errorBox().hidden && rows().length === 25 && /345,249 matching CVEs/.test(meta()) && pageIndicator() === "1 / 13810");
  const beforeDebounce = rankingRequests.length;
  q.value = "first query"; q.listeners.input[0]({ target: q });
  q.value = "latest query"; q.listeners.input[0]({ target: q });
  check("rapid typing coalesces to one pending debounce without issuing requests",
    searchTimers.size === 1 && rankingRequests.length === beforeDebounce);
  flushSearchTimers();
  check("debounce issues only the latest search", rankingRequests.length === beforeDebounce + 1 &&
    new URL(rankingRequests[beforeDebounce].url, "http://test").searchParams.get("q") === "latest query");
  rankingRequests[beforeDebounce].release(payload([], 0));
  await drain();

  // Initial ranking and Retry remain usable even when coverage status fails.
  const initialDoc = makeDocument(indexHtml);
  let failInitial;
  let recoverInitial;
  let initialCount = 0;
  const initialSandbox = {
    ...sandbox, document: initialDoc, window: null,
    fetch: (url) => {
      if (String(url).startsWith("/api/status")) return Promise.reject(new Error("private status failure"));
      initialCount += 1;
      return initialCount === 1
        ? new Promise((resolve, reject) => { failInitial = reject; })
        : new Promise((resolve) => { recoverInitial = (body) => resolve(jsonResponse(body)); });
    }
  };
  initialSandbox.window = initialSandbox;
  initialSandbox.globalThis = initialSandbox;
  vm.createContext(initialSandbox);
  vm.runInContext(appJs, initialSandbox, { filename: "initial-failure-app.js" });
  check("initial ranking starts independently of status", initialCount === 1 && !initialDoc.getElementById("ranking-loading").hidden);
  failInitial(new Error("private initial network failure"));
  await drain();
  check("initial ranking failure shows error without empty result", !initialDoc.getElementById("ranking-error").hidden &&
    initialDoc.getElementById("ranking-loading").hidden && !/No CVE matches/.test(textOf(initialDoc.getElementById("rows"))));
  check("status failure is handled separately without raw exception", /Coverage status unavailable/.test(textOf(initialDoc.getElementById("status-line"))) &&
    !/private/.test(textOf(initialDoc.body)));
  click(initialDoc.getElementById("retry-ranking"));
  recoverInitial(payload(pageA, 345249));
  await drain();
  check("Retry recovers an initial failure despite failed status", initialCount === 2 && initialDoc.getElementById("ranking-error").hidden &&
    initialDoc.getElementById("ranking-loading").hidden && initialDoc.getElementById("rows").children.length === 25);

  check("all failure scenarios produce zero unhandled rejections", rejections.length === 0, rejections.join(" | "));

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
