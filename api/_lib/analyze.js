// Surface analyzer: Snapshot (Contract 1) -> Report (Contract 2).
// Pure: no I/O, no clock. Missing or malformed snapshot fields never throw.

import { RULES } from "./rules.js";

const SEVERITY_RANK = { crit: 0, warn: 1, info: 2, ok: 3 };
const WEIGHT = { crit: 20, warn: 8, info: 1, ok: 0 };

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function rank(finding) {
  return Object.hasOwn(SEVERITY_RANK, finding.severity) ? SEVERITY_RANK[finding.severity] : 4;
}

/**
 * Exposure score for a list of findings.
 * points = 20 × crit + 8 × warn + 1 × info, score = min(100, points).
 * @param {Array<{severity: string}>} findings
 * @returns {{ score: number, level: "low"|"moderate"|"high", counts: {total:number, crit:number, warn:number, info:number, ok:number} }}
 */
export function scoreFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const counts = { total: list.length, crit: 0, warn: 0, info: 0, ok: 0 };
  let points = 0;
  for (const f of list) {
    const severity = isObject(f) ? f.severity : undefined;
    if (!Object.hasOwn(WEIGHT, severity)) continue;
    counts[severity] += 1;
    points += WEIGHT[severity];
  }
  const score = Math.min(100, points);
  const level = score < 25 ? "low" : score < 55 ? "moderate" : "high";
  return { score, level, counts };
}

function stringOr(value, fallback) {
  return typeof value === "string" ? value : fallback;
}

function numberOr(value, fallback) {
  return Number.isFinite(value) ? value : fallback;
}

function buildTarget(s) {
  const url = [s.finalUrl, s.requestedUrl].find((u) => typeof u === "string" && u.trim() !== "") ?? "";
  let host = "";
  if (url) {
    try {
      host = new URL(url).hostname;
    } catch {
      host = "";
    }
  }
  return {
    input: stringOr(s.input, ""),
    url: url.trim(),
    host,
    status: numberOr(s.status, null),
    timingMs: numberOr(s.timingMs, null),
    redirects: Array.isArray(s.redirects) ? s.redirects.length : 0,
    scannedAt: stringOr(s.scannedAt, null),
  };
}

/**
 * Run every rule in the catalog against a snapshot and build the report.
 * Findings are sorted crit, warn, info, ok; catalog order within a severity.
 * @param {object} snapshot Contract 1 Snapshot
 * @returns {object} Contract 2 Report
 */
export function analyze(snapshot) {
  const s = isObject(snapshot) ? snapshot : {};

  const collected = [];
  RULES.forEach((rule, ruleIndex) => {
    const result = rule.run(s);
    const list = result == null ? [] : Array.isArray(result) ? result : [result];
    list.forEach((finding, order) => {
      if (isObject(finding)) collected.push({ finding, ruleIndex, order });
    });
  });

  collected.sort(
    (a, b) => rank(a.finding) - rank(b.finding) || a.ruleIndex - b.ruleIndex || a.order - b.order
  );
  const findings = collected.map((c) => c.finding);
  const { score, level, counts } = scoreFindings(findings);

  return { target: buildTarget(s), score, level, counts, findings };
}
