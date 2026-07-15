"use strict";
// I3: bin/cli.js status() und report() ignorierten früher einen absoluten
// audit.path — sie taten path.join(CWD, rules.audit?.path || …) ohne
// path.isAbsolute-Schutz, während audit() in hooks/lib.js absolute Pfade
// längst respektierte. Folge: mit einem absoluten audit.path voller echter
// Events zeigte `guard status` keine Audit-Zeile, und `guard report` baute
// den kundenseitigen "Nachweis" aus NULL Events — ein Compliance-Report, der
// alles verschweigt. Fix: beide nutzen jetzt denselben auditPathOf()-Helper
// wie audit() (hooks/lib.js) und lib/verify.js.
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const PKG = path.join(__dirname, "..");
const CLI = path.join(PKG, "bin", "cli.js");

function tmpdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
const cleanup = (d) => fs.rmSync(d, { recursive: true, force: true });

function baseRules(overrides = {}) {
  return {
    version: 1,
    mode: "enforce",
    blockedPaths: [{ id: "path.dotenv", glob: "**/.env" }],
    blockedCommands: [],
    piiPatterns: [],
    injectionPatterns: [],
    ...overrides,
  };
}

function run(cli, args, cwd) {
  return spawnSync(process.execPath, [cli, ...args], { cwd, encoding: "utf8" });
}

test("cli status: absoluter audit.path mit N echten Events → Audit-Events-Zeile zählt N, nicht 0", () => {
  const project = tmpdir("guard-status-project-");
  const outsideDir = tmpdir("guard-status-outside-");
  const realAuditPath = path.join(outsideDir, "compliance.jsonl");
  const N = 5;
  const lines = Array.from({ length: N }, (_, i) =>
    JSON.stringify({ ts: `2026-07-1${i}T10:00:00.000Z`, event: i === 0 ? "blocked" : "allowed", ruleId: "path.dotenv" })
  ).join("\n") + "\n";
  fs.writeFileSync(realAuditPath, lines);

  fs.writeFileSync(path.join(project, "guard.rules.json"), JSON.stringify(baseRules({ audit: { enabled: true, path: realAuditPath } })));

  const res = run(CLI, ["status"], project);
  assert.strictEqual(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, new RegExp(`Audit-Events:\\s+${N} gesamt`), `erwarte ${N} Audit-Events, bekam:\n${res.stdout}`);

  cleanup(project);
  cleanup(outsideDir);
});

test("cli report: absoluter audit.path mit N echten Events → Nachweis zählt N Events, nicht 0", () => {
  const project = tmpdir("guard-report-project-");
  const outsideDir = tmpdir("guard-report-outside-");
  const realAuditPath = path.join(outsideDir, "compliance.jsonl");
  const N = 7;
  const lines = [];
  for (let i = 0; i < N; i++) {
    lines.push(JSON.stringify({ ts: `2026-07-1${i % 9}T10:0${i}:00.000Z`, event: i % 2 === 0 ? "blocked" : "allowed", ruleId: "path.dotenv" }));
  }
  fs.writeFileSync(realAuditPath, lines.join("\n") + "\n");

  fs.writeFileSync(path.join(project, "guard.rules.json"), JSON.stringify(baseRules({ audit: { enabled: true, path: realAuditPath } })));

  const res = run(CLI, ["report"], project);
  assert.strictEqual(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, new RegExp(`Ereignisse gesamt: ${N}`), `erwarte ${N} Ereignisse im Report, bekam:\n${res.stdout}`);
  assert.doesNotMatch(res.stdout, /Ereignisse gesamt: 0/, "der Nachweis darf nicht 0 Events zählen, wenn N echte Events an einem absoluten Pfad liegen");

  const reportFile = path.join(project, "guard-report.md");
  assert.ok(fs.existsSync(reportFile), "guard-report.md wurde nicht geschrieben");
  const md = fs.readFileSync(reportFile, "utf8");
  assert.match(md, new RegExp(`Ereignisse gesamt: ${N}`));

  cleanup(project);
  cleanup(outsideDir);
});

test("cli status: relativer benutzerdefinierter audit.path funktioniert weiterhin (keine Regression)", () => {
  const project = tmpdir("guard-status-rel-project-");
  fs.writeFileSync(path.join(project, "guard.rules.json"), JSON.stringify(baseRules({ audit: { enabled: true, path: "logs/guard-audit.jsonl" } })));
  fs.mkdirSync(path.join(project, "logs"), { recursive: true });
  fs.writeFileSync(path.join(project, "logs", "guard-audit.jsonl"), JSON.stringify({ ts: "2026-07-11T10:00:00.000Z", event: "blocked", ruleId: "path.dotenv" }) + "\n");

  const res = run(CLI, ["status"], project);
  assert.strictEqual(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /Audit-Events:\s+1 gesamt/);

  cleanup(project);
});
