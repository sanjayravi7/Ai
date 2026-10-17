/* VULNOVA console front-end.
 *
 * Everything shown here comes from /api/status, /api/ranking and /api/cve/*.
 * The UI never invents a value: missing evidence is rendered as missing, and
 * conflicting CVSS values are rendered side by side with the selected one
 * marked.
 */
(function () {
  "use strict";

  var state = {
    q: "",
    band: "",
    kev: false,
    review: false,
    offset: 0,
    limit: 25,
    selected: null,
    status: null,
    lastRows: []
  };

  function $(id) {
    return document.getElementById(id);
  }

  function h(tag, attrs) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        var value = attrs[key];
        if (value === null || value === undefined) return;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = String(value);
        else if (key.indexOf("on") === 0) node.addEventListener(key.slice(2), value);
        else node.setAttribute(key, value);
      });
    }
    for (var i = 2; i < arguments.length; i += 1) {
      var child = arguments[i];
      if (child === null || child === undefined) continue;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function num(value) {
    if (value === null || value === undefined) return "—";
    return Number(value).toLocaleString("en-US");
  }

  function fixed(value, digits) {
    if (value === null || value === undefined) return "—";
    return Number(value).toFixed(digits);
  }

  function pct(value) {
    if (value === null || value === undefined) return "—";
    return (Number(value) * 100).toFixed(2) + "%";
  }

  function getJSON(url) {
    return fetch(url).then(function (response) {
      return response.json().then(function (body) {
        if (!response.ok) {
          var error = new Error(body.message || body.error || String(response.status));
          error.payload = body;
          error.status = response.status;
          throw error;
        }
        return body;
      });
    });
  }

  function bandChip(band) {
    var key = String(band || "").slice(0, 2).toLowerCase();
    return h("span", { class: "chip " + key, text: band || "—" });
  }

  /* ---------------------------------------------------------------- status */

  function renderCoverage(coverage) {
    var root = $("coverage");
    clear(root);

    var totals = coverage.published_year_totals || [];
    var years = totals.filter(function (row) {
      return row.year >= "2020" && row.year <= "2026";
    });

    var yearBox = h("div", { class: "cov-years" });
    if (!years.length) {
      yearBox.appendChild(h("span", { class: "cov-year", text: "no coverage rows" }));
    }
    years.forEach(function (row) {
      var nonKev = row.records - row.kev_listed;
      var cls = "cov-year " + (nonKev > 0 ? "covered" : "gap");
      yearBox.appendChild(
        h(
          "span",
          {
            class: cls,
            title: row.records + " records published in " + row.year +
              ", of which " + row.kev_listed + " are KEV members"
          },
          row.year + " · " + num(row.records) + " records · " +
            num(nonKev) + " non-KEV"
        )
      );
    });

    var windowText = (coverage.windows || [])
      .map(function (w) {
        return w.source + " " + w.from + " → " + (w.to || "present");
      })
      .join("  ·  ");

    var gaps = coverage.gaps || [];
    var gapNode = gaps.length
      ? h("div", { class: "cov-warn", text: "Remaining gaps: " + gaps.map(function (g) {
          return g.kind + (g.year ? " " + g.year : "") + (g.records ? " (" + g.records + ")" : "");
        }).join("; ") })
      : h("div", { class: "cov-ok", text: "No 2020–2023 non-KEV coverage gap detected in the loaded store." });

    var epss = coverage.epss || {};
    root.appendChild(
      h("div", { class: "cov-block" },
        h("div", { class: "cov-title", text: "Coverage by publication year" }),
        yearBox,
        gapNode
      )
    );
    root.appendChild(
      h("div", { class: "cov-block" },
        h("div", { class: "cov-title", text: "Loaded windows" }),
        h("div", { class: "section-note", text: windowText }),
        h("div", { class: "section-note",
          text: "EPSS: " + num(epss.total) + " scores · " +
            fixed(epss.coverage_of_store, 2) + "% of stored CVEs · " +
            num(epss.unmatched_records) + " scores match no CVE record" })
      )
    );

    if (coverage.kev_unranked && coverage.kev_unranked.length) {
      root.appendChild(
        h("div", { class: "cov-block" },
          h("div", { class: "cov-title", text: "KEV records excluded from ranking" }),
          h("div", { class: "cov-warn",
            text: coverage.kev_unranked.map(function (item) {
              return item.cve_id + " (" + item.reason + ", KEV added " + item.date_added + ")";
            }).join("  ·  ") })
        )
      );
    }

    if (coverage.kev_only_by_id_year && Object.keys(coverage.kev_only_by_id_year).length) {
      root.appendChild(
        h("div", { class: "cov-block" },
          h("div", { class: "cov-title", text: "KEV-only identifiers" }),
          h("div", { class: "section-note",
            text: Object.keys(coverage.kev_only_by_id_year).map(function (year) {
              return year + ": " + num(coverage.kev_only_by_id_year[year]);
            }).join("  ·  ") })
        )
      );
    }
  }

  function loadStatus() {
    return getJSON("/api/status").then(function (status) {
      state.status = status;
      $("status-line").textContent =
        "reference " + status.reference_date +
        " · " + num(status.counts.cve_record) + " CVE records" +
        " · " + num(status.counts.ranking) + " ranked" +
        " · ranking built " + (status.ranking.built_at || "—");
      renderCoverage(status.coverage);
    });
  }

  /* --------------------------------------------------------------- ranking */

  function evidenceCell(row) {
    if (row.review_required) {
      return h("span", { class: "chip warn", text: "INSUFFICIENT EVIDENCE" });
    }
    if (row.evidence_status === "PARTIAL_EVIDENCE") {
      return h("span", { class: "chip missing", text: "PARTIAL" });
    }
    return h("span", { class: "chip", text: "SUFFICIENT" });
  }

  function rowNode(row) {
    var tr = h("tr", { "data-cve": row.cve_id });
    tr.appendChild(h("td", { text: row.cve_id }));
    tr.appendChild(h("td", null, bandChip(
      row.review_required ? row.band + " *" : row.band
    )));
    tr.appendChild(h("td", { class: "num", text: String(row.score) }));
    tr.appendChild(h("td", null, row.kev_listed
      ? h("span", { class: "chip kev", text: "KEV" })
      : h("span", { class: "section-note", text: "—" })));
    tr.appendChild(h("td", {
      class: "num",
      text: row.cvss_value === null ? "—" : fixed(row.cvss_value, 1)
    }));
    tr.appendChild(h("td", {
      class: "num",
      text: row.epss_probability === null ? "—" : pct(row.epss_probability)
    }));
    tr.appendChild(h("td", null,
      row.cvss_conflict
        ? h("span", { class: "chip conflict", text: row.cvss_candidates + " VALUES" })
        : h("span", { class: "section-note", text: String(row.cvss_candidates || 0) })));
    tr.appendChild(h("td", null, evidenceCell(row)));
    tr.appendChild(h("td", { class: "num", text: row.published || "—" }));
    tr.addEventListener("click", function () {
      loadDetail(row.cve_id);
    });
    return tr;
  }

  function renderRows(payload) {
    state.lastRows = payload.rows;
    var body = $("rows");
    clear(body);
    if (!payload.rows.length) {
      var empty = h("tr", null, h("td", { colspan: "9", class: "placeholder",
        text: "No CVE matches the current filters." }));
      body.appendChild(empty);
    }
    payload.rows.forEach(function (row) {
      body.appendChild(rowNode(row));
    });
    var from = payload.total === 0 ? 0 : payload.offset + 1;
    var to = Math.min(payload.offset + payload.limit, payload.total);
    $("list-meta").textContent =
      num(payload.total) + " matching CVEs · showing " + num(from) + "–" + num(to);
    $("page").textContent = (Math.floor(payload.offset / payload.limit) + 1) +
      " / " + Math.max(1, Math.ceil(payload.total / payload.limit));
    $("prev").disabled = payload.offset === 0;
    $("next").disabled = to >= payload.total;
  }

  function loadRanking() {
    var params = new URLSearchParams();
    if (state.q) params.set("q", state.q);
    if (state.band) params.set("band", state.band);
    if (state.kev) params.set("kev", "1");
    if (state.review) params.set("review", "1");
    params.set("limit", String(state.limit));
    params.set("offset", String(state.offset));
    return getJSON("/api/ranking?" + params.toString()).then(renderRows);
  }

  /* ---------------------------------------------------------------- detail */

  function signalTable(signals) {
    var table = h("table", { class: "breakdown" },
      h("thead", null, h("tr", null,
        h("th", { text: "Component" }),
        h("th", { class: "num", text: "Points" }),
        h("th", { text: "Status" }),
        h("th", { text: "Detail" })
      ))
    );
    var body = h("tbody");
    signals.forEach(function (signal) {
      body.appendChild(h("tr", null,
        h("td", null, h("code", { text: signal.name })),
        h("td", { class: "num", text: signal.points + " / " + signal.max_points }),
        h("td", null, h("span", {
          class: "chip " + (signal.status === "OBSERVED" ? "" : "missing"),
          text: signal.status
        })),
        h("td", { class: "detail", text: signal.detail })
      ));
    });
    table.appendChild(body);
    return table;
  }

  function candidateTable(cvss) {
    var table = h("table", { class: "breakdown" },
      h("thead", null, h("tr", null,
        h("th", { text: "Source" }),
        h("th", { text: "Container" }),
        h("th", { text: "Scoring org" }),
        h("th", { text: "Version" }),
        h("th", { class: "num", text: "Value" }),
        h("th", { text: "Severity" }),
        h("th", { text: "Retrieved" }),
        h("th", { text: "" })
      ))
    );
    var body = h("tbody");
    cvss.candidates.forEach(function (cand) {
      var isSelected = cvss.selected && cand.obs_id === cvss.selected.obs_id;
      var tr = h("tr", { class: isSelected ? "selected-row" : "" });
      tr.appendChild(h("td", null, h("code", { text: cand.source })));
      tr.appendChild(h("td", { text: cand.container }));
      tr.appendChild(h("td", { text: cand.scoring_organization || "—" }));
      tr.appendChild(h("td", { text: "v" + (cand.version || "?") }));
      tr.appendChild(h("td", {
        class: "num",
        text: cand.value === null ? "—" : fixed(cand.value, 1)
      }));
      tr.appendChild(h("td", { text: cand.severity || "—" }));
      tr.appendChild(h("td", { class: "detail", text: cand.retrieved_at }));
      tr.appendChild(h("td", null, isSelected
        ? h("span", { class: "chip badge-selected", text: "SELECTED" })
        : h("span", { class: "chip", text: cand.status })));
      body.appendChild(tr);
    });
    table.appendChild(body);
    return table;
  }

  function kv(pairs) {
    var dl = h("dl", { class: "kv" });
    pairs.forEach(function (pair) {
      if (pair === null) return;
      dl.appendChild(h("dt", { text: pair[0] }));
      dl.appendChild(h("dd", { text: pair[1] }));
    });
    return dl;
  }

  function renderDetail(payload) {
    var root = $("detail");
    clear(root);

    root.appendChild(h("div", { class: "detail-head" },
      h("h2", { text: payload.cve_id }),
      bandChip(payload.assessment.review_required
        ? payload.assessment.display_band
        : payload.priority.band),
      payload.observed.kev.status === "LISTED"
        ? h("span", { class: "chip kev", text: "KEV LISTED" })
        : h("span", { class: "chip", text: "NOT IN KEV" })
    ));
    var bandLine = payload.assessment.review_required
      ? payload.assessment.display_band
      : payload.priority.band + " (" + payload.priority.band_consequence + ")";
    root.appendChild(h("div", { class: "meta",
      text: "score " + payload.priority.score + " / " + payload.priority.max_score +
        " · band " + bandLine + " · as of " + payload.as_of }));

    var statusClass = payload.assessment.status === "INSUFFICIENT_EVIDENCE"
      ? "insufficient"
      : (payload.assessment.status === "PARTIAL_EVIDENCE" ? "partial" : "sufficient");
    root.appendChild(h("div", { class: "banner " + statusClass },
      h("span", { class: "label", text: payload.assessment.label }),
      h("span", { text: payload.assessment.statement })
    ));

    if (payload.priority.missing_signals.length) {
      var missing = h("div", { class: "missing-row" });
      payload.priority.missing_signals.forEach(function (name) {
        missing.appendChild(h("span", { class: "chip missing", text: "MISSING: " + name }));
      });
      root.appendChild(missing);
    }

    root.appendChild(h("h3", { text: "Score breakdown" }));
    root.appendChild(signalTable(payload.priority.signals));
    root.appendChild(h("p", { class: "section-note", text: payload.priority.method }));

    var cvss = payload.observed.cvss;
    root.appendChild(h("h3", { text: "CVSS evidence (" + cvss.candidates.length + " source values)" }));
    root.appendChild(candidateTable(cvss));
    if (cvss.conflict.has_conflict) {
      root.appendChild(h("div", { class: "conflict-note" },
        h("strong", { text: "Conflicting values: " }),
        document.createTextNode(
          cvss.conflict.distinct_values.join(" vs ") +
          " · spread " + cvss.conflict.delta + ". " +
          cvss.conflict.comparability_note + " " +
          cvss.conflict.selected_reason
        )
      ));
    } else {
      root.appendChild(h("div", { class: "ok-note", text: cvss.conflict.selected_reason }));
    }

    root.appendChild(h("h3", { text: "EPSS" }));
    root.appendChild(kv([
      ["Status", payload.observed.epss.status],
      ["Probability", payload.observed.epss.probability === null
        ? "not available" : pct(payload.observed.epss.probability)],
      ["Percentile", payload.observed.epss.percentile === undefined ||
        payload.observed.epss.percentile === null
        ? "—" : fixed(payload.observed.epss.percentile, 4)],
      ["Model version", payload.observed.epss.model_version || "—"],
      ["Score date", payload.observed.epss.score_date || "—"]
    ]));

    root.appendChild(h("h3", { text: "KEV" }));
    root.appendChild(kv([
      ["Status", payload.observed.kev.status],
      ["Date added", payload.observed.kev.date_added || "—"],
      ["Vendor / product", payload.observed.kev.vendor
        ? payload.observed.kev.vendor + " / " + (payload.observed.kev.product || "—")
        : "—"]
    ]));

    var prc = payload.publication_recency_context;
    root.appendChild(h("h3", { text: "Publication recency (not exploitation recency)" }));
    root.appendChild(h("p", { class: "section-note", text: prc.statement }));
    root.appendChild(h("p", { class: "section-note",
      text: "Publication date: " + (prc.publication_date || "not available") +
        " · age " + (prc.publication_age_days === null
          ? "unknown" : prc.publication_age_days + " days") +
        " · KEV listing date: " + (prc.kev_listing_date || "not listed") +
        " · days since KEV listing: " + (prc.days_since_kev_listing === null
          ? "n/a" : prc.days_since_kev_listing) }));
    root.appendChild(h("p", { class: "section-note",
      text: "publication_recency does NOT represent: " +
        (prc.does_not_represent || []).join("; ") + "." }));

    root.appendChild(h("h3", { text: "Provenance" }));
    var prov = h("div");
    payload.provenance.sources_present.forEach(function (source) {
      var info = payload.provenance.retrieved[source] || {};
      prov.appendChild(kv([
        [source + " revision", info.revision || "not stated"],
        [source + " retrieved", info.retrieved_at || "—"]
      ]));
    });
    root.appendChild(prov);

    root.appendChild(h("h3", { text: "Coverage" }));
    root.appendChild(h("p", { class: "section-note",
      text: payload.coverage.note + " (" + payload.coverage.status + ")" }));
  }

  function loadDetail(cveId) {
    state.selected = cveId;
    Array.prototype.forEach.call(document.querySelectorAll("tbody tr"), function (tr) {
      if (tr.getAttribute("data-cve") === cveId) tr.classList.add("active");
      else tr.classList.remove("active");
    });
    return getJSON("/api/cve/" + encodeURIComponent(cveId))
      .then(renderDetail)
      .catch(function (error) {
        var root = $("detail");
        clear(root);
        root.appendChild(h("h2", { text: cveId }));
        root.appendChild(h("div", { class: "banner insufficient",
          text: (error.payload && error.payload.message) || error.message }));
      });
  }

  /* ---------------------------------------------------------------- wiring */

  function bind() {
    var searchTimer = null;
    $("q").addEventListener("input", function (event) {
      state.q = event.target.value.trim();
      state.offset = 0;
      if (searchTimer) clearTimeout(searchTimer);
      searchTimer = setTimeout(loadRanking, 180);
    });
    $("band").addEventListener("change", function (event) {
      state.band = event.target.value;
      state.offset = 0;
      loadRanking();
    });
    $("kev").addEventListener("change", function (event) {
      state.kev = event.target.checked;
      state.offset = 0;
      loadRanking();
    });
    $("review").addEventListener("change", function (event) {
      state.review = event.target.checked;
      state.offset = 0;
      loadRanking();
    });
    $("prev").addEventListener("click", function () {
      state.offset = Math.max(0, state.offset - state.limit);
      loadRanking();
    });
    $("next").addEventListener("click", function () {
      state.offset += state.limit;
      loadRanking();
    });
    $("reset").addEventListener("click", function () {
      state.q = "";
      state.band = "";
      state.kev = false;
      state.review = false;
      state.offset = 0;
      $("q").value = "";
      $("band").value = "";
      $("kev").checked = false;
      $("review").checked = false;
      loadRanking();
    });
  }

  function boot() {
    bind();
    loadStatus()
      .then(loadRanking)
      .catch(function (error) {
        $("status-line").textContent = "startup error: " + error.message;
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  window.__vulnova = { state: state, loadDetail: loadDetail, loadRanking: loadRanking };
})();
