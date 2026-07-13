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

// --- I2: audit.enabled:false darf NIE als grünes "✓ Audit-Log schreibbar"
// erscheinen — das Compliance-Artefakt wird schlicht nie geschrieben (audit()
// ist ein No-Op). ok bleibt true (Deaktivieren ist eine legitime Wahl), aber
// ehrlich als Warnung markiert, plus ein Flag am Ergebnis für die Aufrufer. ---

test("verify: audit.enabled:false → auditDisabled:true, KEIN grünes 'Audit-Log schreibbar', stattdessen eine ⚠-Warnung", () => {
  const d = install();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.audit = { enabled: false };
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.auditDisabled, true);
  const auditDetail = r.details.find((dt) => dt.key === "auditWritable");
  assert.ok(auditDetail, "auditWritable-Detail fehlt");
  assert.strictEqual(auditDetail.warn, true, "muss als Warnung markiert sein, nicht stillschweigend grün");
  assert.doesNotMatch(auditDetail.label, /^Audit-Log schreibbar$/, "darf nicht als 'schreibbar' behauptet werden — es wird gar nicht geschrieben");
  assert.match(auditDetail.info, /kein Compliance-Log/i);
  cleanup(d);
});

test("verify: audit.enabled unset (Default: aktiv) → auditDisabled:false, normales grünes 'Audit-Log schreibbar'", () => {
  const d = install();
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.auditDisabled, false);
  const auditDetail = r.details.find((dt) => dt.key === "auditWritable");
  assert.strictEqual(auditDetail.ok, true);
  assert.ok(!auditDetail.warn);
  cleanup(d);
});

// --- Minor: ein SKALARES Regelwerk (kein Objekt) darf nie 'Regelwerk geladen ✓'
// ergeben — sonst greift der Probe-Code (r.audit = …) auf eine primitve und
// wirft eine TypeError, die bin/cli.js fälschlich als Tmpdir-Fehler auswies. ---

test("verify: guard.rules.json ist ein JSON-String ('hallo') → rulesLoaded:false, ok:false, kein Crash", () => {
  const d = install();
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify("hallo"));
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.checks.rulesLoaded, false);
  assert.strictEqual(r.ok, false);
  const rulesDetail = r.details.find((dt) => dt.key === "rules");
  assert.strictEqual(rulesDetail.ok, false);
  cleanup(d);
});

test("verify: guard.rules.json ist ein JSON-Array → rulesLoaded:false, ok:false, kein Crash", () => {
  const d = install();
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify([1, 2, 3]));
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.checks.rulesLoaded, false);
  assert.strictEqual(r.ok, false);
  cleanup(d);
});

// --- A6: guard verify probt JEDE Regel, nicht nur .env / .env.example ---

test("A6: saubere Template-Installation → coverage.probed === coverage.total === 49, ok:true, unprobed:[]", () => {
  const d = install();
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.coverage.total, 49, JSON.stringify(r.coverage));
  assert.strictEqual(r.coverage.probed, 49, JSON.stringify(r.coverage));
  assert.deepStrictEqual(r.coverage.unprobed, []);
  cleanup(d);
});

test("A6: DIE Regression — eine Regel, deren Muster nicht mehr zieht (Pattern geändert, sonst intakt) → ok:false", () => {
  const d = install();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  // cmd.rm-rf bleibt als Regel bestehen (Regelzahl unverändert!), aber ihr
  // Pattern matcht das geerntete Beweismuster ("rm -rf builddir") nicht mehr —
  // genau der reale Fehlerfall "meine handgeschriebene Regel greift gar nicht".
  const rmRf = rules.blockedCommands.find((r) => r.id === "cmd.rm-rf");
  assert.ok(rmRf, "Fixture-Annahme: cmd.rm-rf existiert im Template");
  rmRf.pattern = "DIESES_MUSTER_KANN_NIEMALS_MATCHEN_XYZ";
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, false, "eine Regel, die ihr eigenes Beweismuster nicht mehr blockt, darf NIE ok:true ergeben");
  assert.ok(r.coverage.probed < r.coverage.total, JSON.stringify(r.coverage));
  assert.ok(
    r.details.some((dt) => dt.ok === false && dt.info.includes("cmd.rm-rf") && dt.info.includes("greift nicht")),
    `erwarte eine ehrliche Fehlermeldung für cmd.rm-rf, bekam: ${JSON.stringify(r.details)}`
  );
  cleanup(d);
});

test("A6: leere Regelklasse (blockedCommands: []) → neutral gemeldet, keine falsche Erfolgs-Behauptung für nicht-existente Regeln", () => {
  const d = install();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  const before = rules.blockedCommands.length;
  rules.blockedCommands = [];
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  // Keine Kommando-Regeln mehr aktiv — coverage.total sinkt ehrlich mit,
  // es wird NICHTS behauptet, was nicht mehr existiert.
  assert.strictEqual(r.coverage.total, 49 - before, JSON.stringify(r.coverage));
  const cmdDetail = r.details.find((dt) => dt.key === "class:blockedCommands");
  assert.ok(cmdDetail, "Kommando-Regeln-Detail fehlt");
  assert.strictEqual(cmdDetail.info, "0 Regeln konfiguriert");
  assert.strictEqual(cmdDetail.ok, true, "eine leere Klasse ist kein Fehlschlag, nur nichts zu beweisen");
  cleanup(d);
});

test("A6: eigene Regel ohne Testmuster → ok bleibt true, taucht aber in coverage.unprobed auf (sichtbar als Warnung)", () => {
  const d = install();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.blockedCommands.push({ id: "cmd.mine", pattern: "mein-eigenes-kommando", reason: "custom" });
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.ok(r.coverage.unprobed.includes("cmd.mine"), JSON.stringify(r.coverage));
  assert.strictEqual(r.coverage.total, 50);
  assert.strictEqual(r.coverage.probed, 49);
  const warnDetail = r.details.find((dt) => dt.warn === true);
  assert.ok(warnDetail, "erwarte eine sichtbare ⚠-Zeile für die ungeprüfte eigene Regel");
  assert.ok(warnDetail.info.includes("cmd.mine"));
  cleanup(d);
});

test("A6: eigene Regel MIT selbst gesetztem 'sample'-Feld wird probiert und zählt als probed", () => {
  const d = install();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.blockedCommands.push({ id: "cmd.mine", pattern: "mein-eigenes-kommando", reason: "custom", sample: "mein-eigenes-kommando --jetzt" });
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.ok(!r.coverage.unprobed.includes("cmd.mine"), JSON.stringify(r.coverage));
  assert.strictEqual(r.coverage.total, 50);
  assert.strictEqual(r.coverage.probed, 50);
  cleanup(d);
});

test("A6: eigenes 'sample' überschreibt das mitgelieferte Muster (auch für bekannte Regel-IDs)", () => {
  const d = install();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  // path.dotenv bekäme normalerweise das geerntete Muster ".env" — wir
  // überschreiben es mit einem eigenen, das ebenfalls zieht (**/.env matcht auch
  // "sub/.env"), um zu beweisen, dass die eigene Angabe tatsächlich verwendet wird.
  const dotenv = rules.blockedPaths.find((r) => r.id === "path.dotenv");
  dotenv.sample = "sub/.env";
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.coverage.probed, 49);
  cleanup(d);
});

test("A6: monitor-Modus → alle Regeln weiterhin via would-block probiert, ok:true", () => {
  const d = install({ mode: "monitor" });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.coverage.probed, 49, JSON.stringify(r.coverage));
  assert.strictEqual(r.coverage.total, 49);
  cleanup(d);
});

test("A6: voller 49-Regel-Lauf fasst das echte Audit-Log weiterhin NICHT an", () => {
  const d = install();
  const auditPath = path.join(d, ".claude", "guard-audit.jsonl");
  fs.writeFileSync(auditPath, '{"ts":"2026-01-01T00:00:00.000Z","event":"allowed"}\n');
  const before = fs.readFileSync(auditPath, "utf8");
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.coverage.probed, 49, JSON.stringify(r.coverage));
  assert.strictEqual(fs.readFileSync(auditPath, "utf8"), before, "49-Regel-Lauf darf den Compliance-Trail nicht verändern");
  cleanup(d);
});
