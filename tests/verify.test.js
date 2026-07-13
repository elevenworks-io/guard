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
const HOOK_FILE_NAMES = ["lib.js", "pretool.js", "posttool.js", "prompt.js", "session.js"];

function writeInstall(d, { rules, mode, dropPreToolUse } = {}) {
  const gd = path.join(d, ".claude", "hooks", "guard");
  fs.mkdirSync(gd, { recursive: true });
  for (const f of HOOK_FILE_NAMES) {
    const src = path.join(HOOK_SRC, f);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(gd, f));
  }
  if (mode) rules.mode = mode;
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

// Echte Installation im Temp-Verzeichnis mit dem VOLLEN, ausgelieferten
// 49-Regel-Template — echte Hooks, echte Template-Regeln. Bewusst NUR für die
// drei End-to-End-Läufe unten verwendet (siehe Kommentar dort): jeder Aufruf
// kostet ~51 Kindprozess-Spawns (~3s). Alles, was nur Siegel-/Check-Plumbing
// prüft, nicht die vollständige Regelzahl, läuft über smallInstall().
function install({ mode = "enforce", dropPreToolUse = false, breakRules = false } = {}) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "guard-vf-"));
  const rules = JSON.parse(fs.readFileSync(RULES_SRC, "utf8"));
  if (breakRules) rules.blockedPaths = [];            // entschärft: blockt .env nicht mehr
  return writeInstall(d, { rules, mode, dropPreToolUse });
}

// Kleine 4-Regel-Fixture (eine Regel pro Klasse, mit ECHTEN IDs/Mustern aus dem
// ausgelieferten Template — SHIPPED_SAMPLES greift also weiterhin per ID).
// Reduziert Spawns pro Test von ~51 auf ~5 (~0.3s statt ~3s), OHNE eine
// Verhaltens-Garantie zu verlieren: jeder Test hier prüft Plumbing (Siegel-
// Felder, Checks, Drift, ok:false, Exit-Codes, Audit-Optionen), nicht die
// Regelzahl selbst — die Vollständigkeit des 49-Regel-Templates ist separat
// durch die drei End-to-End-Tests unten UND tests/samples.test.js abgedeckt.
const SMALL_IDS = ["path.dotenv", "cmd.rm-rf", "pii.email", "inj.ignore-previous"];
function smallRules({ ids = SMALL_IDS } = {}) {
  const full = JSON.parse(fs.readFileSync(RULES_SRC, "utf8"));
  const pick = (key) => (full[key] || []).filter((r) => ids.includes(r.id));
  return {
    version: full.version,
    mode: full.mode,
    allowPaths: full.allowPaths,
    blockedPaths: pick("blockedPaths"),
    blockedCommands: pick("blockedCommands"),
    piiPatterns: pick("piiPatterns"),
    injectionPatterns: pick("injectionPatterns"),
    audit: full.audit,
  };
}
function smallInstall({ mode = "enforce", dropPreToolUse = false, ids = SMALL_IDS } = {}) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "guard-vf-sm-"));
  return writeInstall(d, { rules: smallRules({ ids }), mode, dropPreToolUse });
}
const smallTotal = (ids = SMALL_IDS) => ids.length;

const hookOf = (d) => path.join(d, ".claude", "hooks", "guard", "pretool.js");
const cleanup = (d) => fs.rmSync(d, { recursive: true, force: true });

test("verify: saubere Installation → alle Checks grün", () => {
  const d = smallInstall();
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.checks.registered, true);
  assert.strictEqual(r.checks.uniqueIds, true);
  assert.strictEqual(r.checks.blocksSecret, true);
  assert.strictEqual(r.checks.allowsTemplate, true);
  assert.strictEqual(r.checks.auditWritable, true);
  assert.strictEqual(r.mode, "enforce");
  assert.strictEqual(r.coverage.probed, smallTotal());
  assert.strictEqual(r.coverage.total, smallTotal());
  cleanup(d);
});

test("verify: PreToolUse nicht registriert → schlägt fehl", () => {
  const d = smallInstall({ dropPreToolUse: true });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.checks.registered, false);
  cleanup(d);
});

test("verify: entschärfte Regeln → blocksSecret schlägt fehl", () => {
  const d = smallInstall({ ids: ["cmd.rm-rf", "pii.email", "inj.ignore-previous"] }); // kein path.dotenv
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.checks.blocksSecret, false);
  cleanup(d);
});

test("verify: monitor-Modus → erkennt statt blockt, gilt als ok", () => {
  const d = smallInstall({ mode: "monitor" });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.mode, "monitor");
  assert.strictEqual(r.checks.blocksSecret, true, "im monitor zählt would-block als Erkennung");
  assert.strictEqual(r.coverage.probed, smallTotal());
  assert.strictEqual(r.coverage.total, smallTotal());
  cleanup(d);
});

test("verify: fasst das echte Audit-Log NICHT an (Compliance-Trail sauber)", () => {
  const d = smallInstall();
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
  const d = smallInstall();
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
  const d = smallInstall();
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
  const d = smallInstall();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.audit = { enabled: false };
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.checks.blocksSecret, true);
  cleanup(d);
});

// --- I2: audit.enabled:false darf NIE als grünes '✓ Audit-Log schreibbar'
// erscheinen — das Compliance-Artefakt wird schlicht nie geschrieben (audit()
// ist ein No-Op). ok bleibt true (Deaktivieren ist eine legitime Wahl), aber
// ehrlich als Warnung markiert, plus ein Flag am Ergebnis für die Aufrufer. ---

test("verify: audit.enabled:false → auditDisabled:true, KEIN grünes 'Audit-Log schreibbar', stattdessen eine ⚠-Warnung", () => {
  const d = smallInstall();
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
  const d = smallInstall();
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
  const d = smallInstall();
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify("hallo"));
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.checks.rulesLoaded, false);
  assert.strictEqual(r.ok, false);
  const rulesDetail = r.details.find((dt) => dt.key === "rules");
  assert.strictEqual(rulesDetail.ok, false);
  cleanup(d);
});

test("verify: guard.rules.json ist ein JSON-Array → rulesLoaded:false, ok:false, kein Crash", () => {
  const d = smallInstall();
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify([1, 2, 3]));
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.checks.rulesLoaded, false);
  assert.strictEqual(r.ok, false);
  cleanup(d);
});

// --- C1: doppelte Regel-IDs — probeRule()/ruleIdFired() ordnen ein Feuern NUR
// über die ID zu; zwei Regeln mit derselben ID lassen die Probe des Duplikats
// fälschlich als "probiert" durchgehen, obwohl nur die ERSTE (die
// pathBlocked()/commandBlocked() ohnehin allein matcht) je feuert. Harter
// Fehlschlag, kein stiller grüner Erfolg. ---

test("C1: doppelte Regel-ID (path.dotenv zweimal, Duplikat matcht nie) → ok:false, Duplikat benannt", () => {
  // Voller 49-Regel-Lauf (End-to-End #3) — reproduziert exakt den Finding-Fall:
  // eine zusätzliche path.dotenv-Regel, deren eigenes Glob nie matcht, wird
  // OHNE diesen Fix fälschlich als "probiert" mitgezählt (22/22, 50/50 ok:true).
  const d = install();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.blockedPaths.push({ id: "path.dotenv", glob: "**/never-matches-anything.xyz" });
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, false, JSON.stringify(r.details));
  assert.strictEqual(r.checks.uniqueIds, false);
  const dupDetail = r.details.find((dt) => dt.key === "uniqueIds");
  assert.ok(dupDetail, "uniqueIds-Detail fehlt");
  assert.strictEqual(dupDetail.ok, false);
  assert.match(dupDetail.info, /path\.dotenv/);
  cleanup(d);
});

// --- Minor (4. Review): eine Regel OHNE (oder mit leerer) ID ist ein
// eigenständiger Config-Fehler — vorher landete rule.id === undefined
// unbemerkt im selben seen-Set wie echte IDs (nie als Duplikat erkannt) und
// unten im Probe-Lauf als `unprobed: [undefined]`, eine irreführende,
// nicht-handlungsfähige Meldung statt einer ehrlichen Fehlerursache. ---

test("Minor: Regel ohne ID → eigenständiger Config-Fehler, ok:false, kein 'unprobed: [undefined]'", () => {
  const d = smallInstall();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.blockedCommands.push({ pattern: "ohne-id-regel", reason: "custom" }); // kein id-Feld
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, false, JSON.stringify(r.details));
  assert.strictEqual(r.checks.uniqueIds, false);
  assert.ok(!r.coverage.unprobed.includes(undefined), "darf kein 'undefined' in unprobed melden");
  const detail = r.details.find((dt) => dt.key === "missingId");
  assert.ok(detail, "missingId-Detail fehlt");
  assert.strictEqual(detail.ok, false);
  assert.match(detail.info, /ohne \(oder leere\) ID/);
  cleanup(d);
});

// --- I2: checks.blocksSecret geht in `ok` ein, aber MUSS eine sichtbare
// Detail-Zeile bekommen — sonst: alle Zeilen grün, dann "✕ Verifikation
// fehlgeschlagen. Ursache oben." ohne dass oben je eine Ursache stand. ---

test("I2: fehlende Regel path.dotenv → blocksSecret-Detail sichtbar mit Grund, ok:false", () => {
  const d = smallInstall({ ids: ["cmd.rm-rf", "pii.email", "inj.ignore-previous"] });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.checks.blocksSecret, false);
  const detail = r.details.find((dt) => dt.key === "blocksSecret");
  assert.ok(detail, "blocksSecret-Detail fehlt — I2: undiagnostizierbarer Fehlschlag");
  assert.strictEqual(detail.ok, false);
  assert.match(detail.info, /NICHT blockiert/);
  cleanup(d);
});

test("I2: vorhandene Regel path.dotenv → blocksSecret-Detail sichtbar und grün", () => {
  const d = smallInstall();
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.checks.blocksSecret, true);
  const detail = r.details.find((dt) => dt.key === "blocksSecret");
  assert.ok(detail, "blocksSecret-Detail fehlt");
  assert.strictEqual(detail.ok, true);
  assert.match(detail.info, /\.env → blockiert/);
  cleanup(d);
});

// --- CRITICAL (4. Review): blocksSecret war `probedIds.has("path.dotenv")` —
// fragt nur "hat IRGENDEINE Regel mit dieser ID auf ihrem (nutzer-
// überschreibbaren) Muster gefeuert?", nie "wird .env tatsächlich blockiert?".
// Genau guards EIGENE Fehlermeldung ("Regel greift nicht auf ihr Testmuster —
// Muster geändert? Eigenes 'sample' setzen.") führt einen Nutzer, der das
// dotenv-Glob verengt hat (**/.env → **/.env.production), direkt in die
// Falle: ein passendes eigenes "sample" macht die Probe wieder grün, obwohl
// `Read .env` im selben Projekt weiterhin ungehindert durchläuft. Das ist die
// Regression, die vor diesem Fix voll grün war. ---

test("CRITICAL: path.dotenv-Glob verengt + Nutzer folgt guards eigenem Rat (passendes eigenes sample) → blocksSecret bleibt false, ok:false", () => {
  const d = smallInstall(); // enthält path.dotenv mit dem ausgelieferten **/.env-Glob
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  const dotenv = rules.blockedPaths.find((r) => r.id === "path.dotenv");
  assert.ok(dotenv, "Fixture-Annahme: path.dotenv existiert");
  dotenv.glob = "**/.env.production"; // .env selbst matcht dieses Glob nicht mehr
  dotenv.sample = ".env.production";  // genau der Rat aus guards eigener Fehlermeldung befolgt
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  // Die Regel selbst feuert weiterhin auf ihr (jetzt engeres) Testmuster —
  // das alte, fehlerhafte `probedIds.has("path.dotenv")` wäre hier grün
  // gewesen. Der neue, ID-unabhängige Spawn gegen das ECHTE ".env" muss das
  // trotzdem als Fehlschlag erkennen.
  assert.strictEqual(r.checks.blocksSecret, false, JSON.stringify(r.details));
  assert.strictEqual(r.ok, false, "ein wide-open .env darf NIE ok:true ergeben, egal wie grün die übrigen Zeilen sind");
  const detail = r.details.find((dt) => dt.key === "blocksSecret");
  assert.ok(detail);
  assert.strictEqual(detail.ok, false);
  assert.match(detail.info, /NICHT blockiert/, "die Detail-Zeile muss ehrlich sagen, dass .env NICHT blockiert wird");
  cleanup(d);
});

test("CRITICAL/monitor: .env → would-block + exit 0 erfüllt blocksSecret weiterhin (monitor-Modus nicht kaputt gemacht)", () => {
  const d = smallInstall({ mode: "monitor" });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.checks.blocksSecret, true, JSON.stringify(r.details));
  const detail = r.details.find((dt) => dt.key === "blocksSecret");
  assert.ok(detail);
  assert.strictEqual(detail.ok, true);
  assert.match(detail.info, /würde blockiert \(monitor\)/);
  cleanup(d);
});

// --- A6: guard verify probt JEDE Regel, nicht nur .env / .env.example ---

test("A6: saubere Template-Installation → coverage.probed === coverage.total === 49, ok:true, unprobed:[], Audit-Log unangetastet", () => {
  const d = install();
  const auditPath = path.join(d, ".claude", "guard-audit.jsonl");
  fs.writeFileSync(auditPath, '{"ts":"2026-01-01T00:00:00.000Z","event":"allowed"}\n');
  const before = fs.readFileSync(auditPath, "utf8");

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.coverage.total, 49, JSON.stringify(r.coverage));
  assert.strictEqual(r.coverage.probed, 49, JSON.stringify(r.coverage));
  assert.deepStrictEqual(r.coverage.unprobed, []);
  // A6 (voller 49-Regel-Lauf fasst das echte Audit-Log weiterhin NICHT an):
  assert.strictEqual(fs.readFileSync(auditPath, "utf8"), before, "49-Regel-Lauf darf den Compliance-Trail nicht verändern");
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
  const d = smallInstall();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  const before = rules.blockedCommands.length;
  rules.blockedCommands = [];
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  // Keine Kommando-Regeln mehr aktiv — coverage.total sinkt ehrlich mit,
  // es wird NICHTS behauptet, was nicht mehr existiert.
  assert.strictEqual(r.coverage.total, smallTotal() - before, JSON.stringify(r.coverage));
  const cmdDetail = r.details.find((dt) => dt.key === "class:blockedCommands");
  assert.ok(cmdDetail, "Kommando-Regeln-Detail fehlt");
  assert.strictEqual(cmdDetail.info, "0 Regeln konfiguriert");
  assert.strictEqual(cmdDetail.ok, true, "eine leere Klasse ist kein Fehlschlag, nur nichts zu beweisen");
  cleanup(d);
});

test("A6: eigene Regel ohne Testmuster → ok bleibt true, taucht aber in coverage.unprobed auf (sichtbar als Warnung)", () => {
  const d = smallInstall();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.blockedCommands.push({ id: "cmd.mine", pattern: "mein-eigenes-kommando", reason: "custom" });
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.ok(r.coverage.unprobed.includes("cmd.mine"), JSON.stringify(r.coverage));
  assert.strictEqual(r.coverage.total, smallTotal() + 1);
  assert.strictEqual(r.coverage.probed, smallTotal());
  const warnDetail = r.details.find((dt) => dt.warn === true);
  assert.ok(warnDetail, "erwarte eine sichtbare ⚠-Zeile für die ungeprüfte eigene Regel");
  assert.ok(warnDetail.info.includes("cmd.mine"));
  cleanup(d);
});

test("A6: eigene Regel MIT selbst gesetztem 'sample'-Feld wird probiert und zählt als probed", () => {
  const d = smallInstall();
  const rulesPath = path.join(d, "guard.rules.json");
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  rules.blockedCommands.push({ id: "cmd.mine", pattern: "mein-eigenes-kommando", reason: "custom", sample: "mein-eigenes-kommando --jetzt" });
  fs.writeFileSync(rulesPath, JSON.stringify(rules, null, 2));

  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.ok(!r.coverage.unprobed.includes("cmd.mine"), JSON.stringify(r.coverage));
  assert.strictEqual(r.coverage.total, smallTotal() + 1);
  assert.strictEqual(r.coverage.probed, smallTotal() + 1);
  cleanup(d);
});

test("A6: eigenes 'sample' überschreibt das mitgelieferte Muster (auch für bekannte Regel-IDs)", () => {
  const d = smallInstall();
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
  assert.strictEqual(r.coverage.probed, smallTotal());
  cleanup(d);
});

test("A6: monitor-Modus → alle Regeln weiterhin via would-block probiert, ok:true", () => {
  const d = smallInstall({ mode: "monitor" });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.coverage.probed, smallTotal(), JSON.stringify(r.coverage));
  assert.strictEqual(r.coverage.total, smallTotal());
  cleanup(d);
});

// --- Restore der beim Test-Trim (109s → 16s) verlorenen Vollständigkeits-
// Garantie: "monitor-Modus → alle Regeln via would-block probiert" prüfte
// vorher 49/49 auf dem vollen ausgelieferten Template, wurde beim Trim auf
// die kleine 4-Regel-Fixture verkürzt (der Test oben). Ein einziger
// zusätzlicher voller Lauf hier hält die 49-Regel-Garantie günstig aufrecht
// (~3s), ohne zu den 16s der übrigen Suite viel hinzuzufügen. ---

test("A6: monitor-Modus, volles 49-Regel-Template → alle Regeln via would-block probiert, probed===total===49, ok:true", () => {
  const d = install({ mode: "monitor" });
  const r = runVerify({ cwd: d, hookPath: hookOf(d) });
  assert.strictEqual(r.ok, true, JSON.stringify(r.details));
  assert.strictEqual(r.mode, "monitor");
  assert.strictEqual(r.coverage.total, 49, JSON.stringify(r.coverage));
  assert.strictEqual(r.coverage.probed, 49, JSON.stringify(r.coverage));
  assert.deepStrictEqual(r.coverage.unprobed, []);
  cleanup(d);
});
