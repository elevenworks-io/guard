"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { runFixture, collectRuleIds } = require("./runner.js");

const ATTACK_DIR = path.join(__dirname, "attacks");
const RULES = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "templates", "guard.rules.json"), "utf8"));
const RULE_IDS = collectRuleIds(RULES);
const VALID_EXPECT = new Set(["blocked", "allowed", "warn", "known-gap", "injection"]);

function loadFixtures() {
  const out = [];
  for (const file of fs.readdirSync(ATTACK_DIR).filter((f) => f.endsWith(".jsonl"))) {
    const lines = fs.readFileSync(path.join(ATTACK_DIR, file), "utf8").split("\n").filter((l) => l.trim());
    lines.forEach((line, i) => out.push({ file, lineNo: i + 1, ...JSON.parse(line) }));
  }
  return out;
}

function evaluate(fx, r) {
  if (fx.expect === "blocked") {
    assert.strictEqual(r.exitCode, 2, `expected block for "${fx.desc}"\nstderr: ${r.stderr}`);
    const ev = r.auditEvents.find((e) => e.event === "blocked");
    assert.ok(ev, `no "blocked" audit event for "${fx.desc}"`);
    // pretool blocks carry top-level ruleId; PII-prompt blocks carry it per finding.
    const firedIds = ev.ruleId ? [ev.ruleId] : (ev.findings || []).map((f) => f.ruleId);
    assert.ok(firedIds.includes(fx.rule), `wrong rule fired for "${fx.desc}" (got: ${firedIds.join(", ")})`);
    if (fx.reasonSnapshot) assert.ok(r.stderr.includes(fx.reasonSnapshot), `reason drift for "${fx.desc}"`);
  } else if (fx.expect === "allowed") {
    assert.strictEqual(r.exitCode, 0, `expected allow for "${fx.desc}"\nstderr: ${r.stderr}`);
    assert.strictEqual(r.stdout.trim(), "", `unexpected hint for "${fx.desc}"`);
  } else if (fx.expect === "warn") {
    assert.strictEqual(r.exitCode, 0, `warn must not block "${fx.desc}"`);
    const ev = r.auditEvents.find((e) => e.event === "warned");
    assert.ok(ev, `no "warned" audit event for "${fx.desc}"`);
    assert.ok((ev.findings || []).some((f) => f.ruleId === fx.rule), `wrong warn rule for "${fx.desc}"`);
    assert.ok(r.stdout.includes("[guard]"), `no stdout hint for "${fx.desc}"`);
  } else if (fx.expect === "injection") {
    assert.strictEqual(r.exitCode, 0, `detector must not block "${fx.desc}"`);
    const ev = r.auditEvents.find((e) => e.event === "injection-detected");
    assert.ok(ev, `no "injection-detected" audit event for "${fx.desc}"`);
    assert.ok((ev.findings || []).some((f) => f.ruleId === fx.rule), `wrong injection rule for "${fx.desc}"`);
    assert.match(r.stdout, /injection|Injection/, `expected a warning in stdout for "${fx.desc}"`);
  } else if (fx.expect === "known-gap") {
    if (r.exitCode === 2) {
      throw new Error(`GAP CLOSED: ${fx.desc} — Fixture auf "blocked" umstellen und die README-Grenze streichen.`);
    }
    assert.strictEqual(r.exitCode, 0, `known-gap unexpectedly errored for "${fx.desc}"`);
  }
}

const fixtures = loadFixtures();
for (const fx of fixtures) {
  test(`[${fx.file}:${fx.lineNo}] ${fx.desc}`, () => evaluate(fx, runFixture(fx)));
}

// ---- Integritäts-Meta-Tests (Spec 3.5) ----
test("meta: every fixture schema is valid", () => {
  for (const fx of fixtures) {
    assert.ok(fx.desc && fx.hook && fx.input && VALID_EXPECT.has(fx.expect), `invalid fixture [${fx.file}:${fx.lineNo}]`);
    if (fx.expect === "blocked" || fx.expect === "warn" || fx.expect === "injection") assert.ok(fx.rule, `missing rule id [${fx.file}:${fx.lineNo}]`);
  }
});
test("meta: fixtures reference only existing rule ids", () => {
  for (const fx of fixtures) {
    if (fx.rule) assert.ok(RULE_IDS.has(fx.rule), `unknown rule id "${fx.rule}" [${fx.file}:${fx.lineNo}]`);
  }
});
test("meta: rule ids are unique", () => {
  const all = [...(RULES.blockedPaths || []), ...(RULES.blockedCommands || []), ...(RULES.piiPatterns || [])].map((r) => r.id);
  assert.strictEqual(all.length, new Set(all).size, "duplicate rule id");
});
test("meta: every rule id is covered by >=1 blocked/warn/injection fixture", () => {
  const covered = new Set(fixtures.filter((f) => ["blocked", "warn", "injection"].includes(f.expect)).map((f) => f.rule));
  const missing = [...RULE_IDS].filter((id) => !covered.has(id));
  assert.strictEqual(missing.length, 0, `rules without a fixture: ${missing.join(", ")}`);
});
