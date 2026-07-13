"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { runVerify } = require("../lib/verify.js");

const PKG = path.join(__dirname, "..");
const HOOK_SRC = path.join(PKG, "hooks");
const RULES_SRC = path.join(PKG, "templates", "guard.rules.json");

// Echte Installation im Temp-Verzeichnis: echte Hooks, echte Template-Regeln.
function install({ mode = "enforce", dropPreToolUse = false, breakRules = false } = {}) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "guard-vf-"));
  const gd = path.join(d, ".claude", "hooks", "guard");
  fs.mkdirSync(gd, { recursive: true });
  for (const f of ["lib.js", "pretool.js", "posttool.js", "prompt.js", "session.js"]) {
    const src = path.join(HOOK_SRC, f);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(gd, f));
  }
  const rules = JSON.parse(fs.readFileSync(RULES_SRC, "utf8"));
  rules.mode = mode;
  if (breakRules) rules.blockedPaths = [];            // entschärft: blockt .env nicht mehr
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify(rules, null, 2));
  const hooks = {
    PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/pretool.js"' }] }],
    PostToolUse: [{ matcher: "Read|Bash", hooks: [{ type: "command", command: 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/posttool.js"' }] }],
    UserPromptSubmit: [{ hooks: [{ type: "command", command: 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/prompt.js"' }] }],
    SessionStart: [{ matcher: "startup|resume", hooks: [{ type: "command", command: 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/session.js"' }] }],
  };
  if (dropPreToolUse) delete hooks.PreToolUse;
  fs.writeFileSync(path.join(d, ".claude", "settings.json"), JSON.stringify({ hooks }, null, 2));
  return d;
}
const hookOf = (d) => path.join(d, ".claude", "hooks", "guard", "pretool.js");
const cleanup = (d) => fs.rmSync(d, { recursive: true, force: true });

test("verify: saubere Installation → alle Checks grün", () => {
  const d = install();
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.checks.registered, true);
  assert.strictEqual(r.checks.blocksSecret, true);
  assert.strictEqual(r.checks.allowsTemplate, true);
  assert.strictEqual(r.checks.auditWritable, true);
  assert.strictEqual(r.mode, "enforce");
  cleanup(d);
});

test("verify: PreToolUse nicht registriert → schlägt fehl", () => {
  const d = install({ dropPreToolUse: true });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.checks.registered, false);
  cleanup(d);
});

test("verify: entschärfte Regeln → blocksSecret schlägt fehl", () => {
  const d = install({ breakRules: true });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.checks.blocksSecret, false);
  cleanup(d);
});

test("verify: monitor-Modus → erkennt statt blockt, gilt als ok", () => {
  const d = install({ mode: "monitor" });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.mode, "monitor");
  assert.strictEqual(r.checks.blocksSecret, true, "im monitor zählt would-block als Erkennung");
  cleanup(d);
});

test("verify: fasst das echte Audit-Log NICHT an (Compliance-Trail sauber)", () => {
  const d = install();
  const auditPath = path.join(d, ".claude", "guard-audit.jsonl");
  fs.writeFileSync(auditPath, '{"ts":"2026-01-01T00:00:00.000Z","event":"allowed"}\n');
  const before = fs.readFileSync(auditPath, "utf8");
  runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(fs.readFileSync(auditPath, "utf8"), before, "verify darf den Compliance-Trail nicht verändern");
  cleanup(d);
});

// --- C2 / I1: audit.path ist ein first-class, shipped config field und kann
// absolut sein — der Probe-Hook darf ihn NIE benutzen, sonst landen
// synthetische Test-Events im ECHTEN Compliance-Log. ---

test("verify: audit.path ABSOLUT (echte Datei außerhalb des Projekts) → bleibt byte-identisch, ok:true", () => {
  const d = install();
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-real-audit-"));
  const realAuditPath = path.join(outsideDir, "compliance.jsonl");
  const seedLine = '{"ts":"2020-01-01T00:00:00.000Z","event":"echtes-produktions-event"}\n';
  fs.writeFileSync(realAuditPath, seedLine);

  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.audit = { enabled: true, path: realAuditPath };
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(fs.readFileSync(realAuditPath, "utf8"), seedLine, "das ECHTE Compliance-Log (absoluter Pfad) darf keine synthetischen Probe-Events bekommen");
  fs.rmSync(outsideDir, { recursive: true, force: true });
  cleanup(d);
});

test("verify: audit.path CUSTOM RELATIV (z.B. logs/guard-audit.jsonl) → ok:true (Probe findet ihre eigenen Events trotzdem)", () => {
  const d = install();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.audit = { enabled: true, path: "logs/guard-audit.jsonl" };
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.checks.blocksSecret, true);
  cleanup(d);
});

test("verify: audit.enabled:false im echten Regelwerk → ok:true (Probe protokolliert trotzdem intern, um sich selbst zu prüfen)", () => {
  const d = install();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.audit = { enabled: false };
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.checks.blocksSecret, true);
  cleanup(d);
});
