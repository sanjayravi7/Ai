#!/usr/bin/env node
/*
 * CVSS presentation regression tests — DEF-1 and DEF-3.
 *
 * These exercise the *rendering logic* extracted from static/app.js
 * (window.__vulnova.cvssPresentation). They are logic tests, not screenshots.
 *
 * Cases 1-4 use real CVE payloads fetched from a running server. Case 5 has
 * no real counterpart — the API always emits `comparable` — so it is produced
 * by deleting the field from a real payload, which is exactly the incomplete
 * metadata the fix must handle explicitly.
 *
 *   node tools/cvss_presentation_check.js --base http://127.0.0.1:8000
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
const ROOT = path.resolve(__dirname, "..");

/* --------------------------------------------------------------- harness */

const results = [];
function check(name, condition, detail) {
  results.push({ name, ok: !!condition, detail: detail || "" });
  const mark = condition ? "PASS" : "FAIL";
  console.log(`  [${mark}] ${name}${condition ? "" : "  -> " + (detail || "")}`);
}

// Minimal document: readyState "loading" means app.js installs its handlers
// but never boots, so no fetch or DOM lookups happen at load time.
const sandbox = {
  document: { readyState: "loading", addEventListener: () => {} },
  console,
  setTimeout,
  clearTimeout,
  URLSearchParams,
  encodeURIComponent,
  fetch,
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(
  fs.readFileSync(path.join(ROOT, "vulnova/static/app.js"), "utf8"),
  sandbox,
  { filename: "app.js" }
);

const P = sandbox.__vulnova && sandbox.__vulnova.cvssPresentation;
if (!P) {
  console.error("FAIL: app.js did not expose window.__vulnova.cvssPresentation");
  process.exit(2);
}

async function payload(cveId) {
  const response = await fetch(`${BASE}/api/cve/${encodeURIComponent(cveId)}`);
  if (!response.ok) throw new Error(`${cveId}: HTTP ${response.status}`);
  const body = await response.json();
  return body.observed.cvss;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

/* ---------------------------------------------------------------- cases */

async function main() {
  console.log(`CVSS presentation regression tests against ${BASE}`);
  console.log("(rendering-logic tests — not screenshots)\n");

  const conflicting = await payload("CVE-2026-41940");   // 9.3 v4.0 vs 9.8 v3.1
  const equalCross = await payload("CVE-2015-3306");     // 10.0 v2.0 vs 10.0 v3.1
  const equalSame = await payload("CVE-2021-23203");     // 7.5 v3.1 vs 7.5 v3.1
  const missing = await payload("CVE-2025-52097");       // one MISSING_FROM_SOURCE row

  /* ---- case 1: different values, different versions ---- */
  console.log("case 1 — different values, different CVSS versions (CVE-2026-41940)");
  {
    const heading = P.heading(conflicting);
    const state = P.state(conflicting);
    const notice = P.notice(conflicting);
    check("heading counts 2 observed values",
      heading === "CVSS evidence \u2014 2 observed values", heading);
    check("state is not_comparable", state === "not_comparable", state);
    check("warning names non-comparability",
      notice.text.includes("NOT directly comparable"), notice.text.slice(0, 120));
    check("conflict note styling", notice.className === "conflict-note", notice.className);
    check("both values are named in the notice",
      notice.text.includes("9.3") && notice.text.includes("9.8"), notice.text.slice(0, 160));
    check("selected value and rule are explained",
      /Selected .*v4\.0/.test(notice.text) && /highest CVSS version wins/.test(notice.text));
  }

  /* ---- case 2: equal values, different versions (DEF-1) ---- */
  console.log("\ncase 2 — equal values, different CVSS versions (CVE-2015-3306)  [DEF-1]");
  {
    const hasConflict = conflicting.conflict.has_conflict;
    const heading = P.heading(equalCross);
    const state = P.state(equalCross);
    const notice = P.notice(equalCross);
    check("precondition: has_conflict is false",
      equalCross.conflict.has_conflict === false,
      String(equalCross.conflict.has_conflict));
    check("precondition: comparable is false",
      equalCross.conflict.comparable === false,
      String(equalCross.conflict.comparable));
    check("heading counts 2 observed values",
      heading === "CVSS evidence \u2014 2 observed values", heading);
    check("warning is shown even though has_conflict is false",
      notice.text.includes("NOT directly comparable"), notice.text);
    check("state is not_comparable, not comparable",
      state === "not_comparable", state);
    check("equal numbers are not called directly comparable",
      !/directly comparable(?!\.)/.test(notice.text.replace("NOT directly comparable", "")),
      notice.text);
    check("notice styling is the conflict style",
      notice.className === "conflict-note", notice.className);
    check("agreement is still reported", /agree/.test(notice.text), notice.text);
    void hasConflict;
  }

  /* ---- case 3: equal values, same version ---- */
  console.log("\ncase 3 — equal values, same CVSS version (CVE-2021-23203)");
  {
    const heading = P.heading(equalSame);
    const state = P.state(equalSame);
    const notice = P.notice(equalSame);
    check("precondition: both values are 7.5 v3.1",
      equalSame.candidates.every((c) => c.value === 7.5 && c.version === "3.1"));
    check("heading counts 2 observed values",
      heading === "CVSS evidence \u2014 2 observed values", heading);
    check("state is comparable", state === "comparable", state);
    check("no false non-comparability warning",
      !notice.text.includes("NOT directly comparable"), notice.text);
    check("same-scale rationale is shown",
      /share a scale/.test(notice.text), notice.text.slice(0, 160));
    check("notice styling is the ok style",
      notice.className === "ok-note", notice.className);
  }

  /* ---- case 4: missing CVSS values (DEF-3) ---- */
  console.log("\ncase 4 — no observed values, one source reports none (CVE-2025-52097)  [DEF-3]");
  {
    const heading = P.heading(missing);
    const state = P.state(missing);
    const notice = P.notice(missing);
    const counts = P.counts(missing);
    check("counts: 0 observed, 1 missing",
      counts.observed === 0 && counts.missing === 1, JSON.stringify(counts));
    check("heading reports zero observed values",
      heading === "CVSS evidence \u2014 0 observed values \u00b7 1 source reports none", heading);
    check("heading does not claim a source value exists",
      !/\(1 source values\)/.test(heading), heading);
    check("no phantom score is rendered", !/9\.\d|10\.0/.test(heading), heading);
    check("comparability is not applied to a single source",
      state === "not_applicable", state);
    check("no comparability claim is made",
      !notice.text.includes("directly comparable"), notice.text);
    check("explains that no source states a score",
      /No source states a CVSS base score/.test(notice.text), notice.text);
  }

  /* ---- case 5: missing / incomplete comparability metadata ---- */
  console.log("\ncase 5 — missing comparability metadata (mutated real payload)");
  {
    const noField = clone(equalSame);
    delete noField.conflict.comparable;
    const noConflict = clone(equalSame);
    delete noConflict.conflict;

    const s1 = P.state(noField);
    const n1 = P.notice(noField);
    check("absent `comparable` is not read as true", s1 !== "comparable", s1);
    check("absent `comparable` is reported as unknown", s1 === "unknown", s1);
    check("unknown metadata is stated explicitly",
      /not stated by the payload/.test(n1.text), n1.text);
    check("unknown metadata warns against assuming comparability",
      /must not be treated as directly comparable/.test(n1.text), n1.text);
    check("unknown metadata uses the unknown style",
      n1.className === "unknown-note", n1.className);

    const s2 = P.state(noConflict);
    const n2 = P.notice(noConflict);
    check("absent conflict object is reported as unknown", s2 === "unknown", s2);
    check("absent conflict object does not crash", typeof n2.text === "string", typeof n2.text);

    const nullable = clone(equalSame);
    nullable.conflict.comparable = null;
    check("null `comparable` is not read as true",
      P.state(nullable) === "unknown", P.state(nullable));
  }

  /* ---- counting and pluralisation edge cases ---- */
  console.log("\nedge cases — counting and pluralisation");
  {
    const twoMissing = {
      candidates: [
        { status: "MISSING_FROM_SOURCE", value: null },
        { status: "MISSING_FROM_SOURCE", value: null },
      ],
      conflict: { comparable: null },
    };
    check("two missing sources are pluralised",
      P.heading(twoMissing) ===
        "CVSS evidence \u2014 0 observed values \u00b7 2 sources report none",
      P.heading(twoMissing));

    const mixed = {
      candidates: [
        { status: "OBSERVED", value: 9.8 },
        { status: "NOT_STATED_BY_SOURCE", value: null },
        { status: "UNAVAILABLE", value: null },
      ],
      conflict: { comparable: null },
    };
    check("mixed states are all reported",
      P.heading(mixed) ===
        "CVSS evidence \u2014 1 observed value \u00b7 1 source value not stated \u00b7 1 source unavailable",
      P.heading(mixed));
    check("one observed value cannot be compared",
      P.state(mixed) === "not_applicable", P.state(mixed));

    const empty = { candidates: [], conflict: null };
    check("no candidates yields an explicit heading",
      P.heading(empty) === "CVSS evidence \u2014 no source rows loaded", P.heading(empty));

    const placeholderWithValue = {
      candidates: [{ status: "MISSING_FROM_SOURCE", value: 9.8 }],
      conflict: { comparable: true },
    };
    check("a value on a non-observed row is not counted as observed",
      P.counts(placeholderWithValue).observed === 0,
      JSON.stringify(P.counts(placeholderWithValue)));
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length} PASS, ${failed.length} FAIL`);
  if (failed.length) {
    failed.forEach((f) => console.log(`  FAILED: ${f.name} ${f.detail}`));
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("cvss presentation check crashed:", error.message);
  process.exit(2);
});
