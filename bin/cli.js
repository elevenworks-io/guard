#!/usr/bin/env node
// @elevenworks/guard — CLI
// Befehle: init (Hooks im Projekt installieren), status (aktive Regeln zeigen)
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");

const { SEAL_REL, HOOK_FILES, realRoot } = require("../hooks/lib.js");

const PKG_ROOT = path.join(__dirname, "..");
const CWD = process.cwd();
const CLAUDE_DIR = path.join(CWD, ".claude");
const HOOKS_DIR = path.join(CLAUDE_DIR, "hooks", "guard");
const SETTINGS = path.join(CLAUDE_DIR, "settings.json");
const RULES_TARGET = path.join(CWD, "guard.rules.json");
const GITIGNORE = path.join(CWD, ".gitignore");

const c = {
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
};

function countRules(rules) {
  return (
    (rules.blockedPaths?.length || 0) +
    (rules.blockedCommands?.length || 0) +
    (rules.piiPatterns?.length || 0) +
    (rules.injectionPatterns?.length || 0)
  );
}

// Trägt die beiden maschinenlokalen Artefakte (Compliance-Log, Siegel) ins
// Projekt-.gitignore ein — tatsächlich, nicht nur als Konsolen-Hinweis (der
// wird zu leicht überlesen). Erstellt die Datei bei Bedarf, dupliziert nie,
// verändert bestehenden Inhalt nie.
function ensureGitignore() {
  const entries = [".claude/guard-audit.jsonl", ".claude/guard-verified.json"];
  let content = fs.existsSync(GITIGNORE) ? fs.readFileSync(GITIGNORE, "utf8") : "";
  const lines = new Set(content.split("\n").map((l) => l.trim()).filter(Boolean));
  const toAdd = entries.filter((e) => !lines.has(e));
  if (toAdd.length === 0) return;
  if (content.length && !content.endsWith("\n")) content += "\n";
  content += toAdd.join("\n") + "\n";
  fs.writeFileSync(GITIGNORE, content);
  console.log(`  ${c.green("✓")} .gitignore → ${c.dim(toAdd.join(", "))}`);
}

function loadRulesFile() {
  for (const p of [RULES_TARGET, path.join(CLAUDE_DIR, "guard.rules.json")]) {
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
  }
  return null;
}

function init() {
  console.log(c.bold("\n  @elevenworks/guard — init\n"));

  // 1) Hook-Scripts kopieren — HOOK_FILES ist die EINZIGE Quelle der Wahrheit
  // (auch computeFingerprint() hasht genau diese Liste). Eine eigene Kopie
  // hier wäre eine zweite Liste, die unbemerkt von der ersten abweichen kann —
  // genau die Lücke, die der Fingerabdruck schließen soll.
  fs.mkdirSync(HOOKS_DIR, { recursive: true });
  for (const f of HOOK_FILES) {
    fs.copyFileSync(path.join(PKG_ROOT, "hooks", f), path.join(HOOKS_DIR, f));
  }
  console.log(`  ${c.green("✓")} Hook-Scripts → ${c.dim(".claude/hooks/guard/")}`);

  // 2) Regeln kopieren (bestehende nie überschreiben)
  if (!fs.existsSync(RULES_TARGET)) {
    fs.copyFileSync(path.join(PKG_ROOT, "templates", "guard.rules.json"), RULES_TARGET);
    console.log(`  ${c.green("✓")} Regelwerk → ${c.dim("guard.rules.json")}`);
  } else {
    console.log(`  ${c.dim("→")} guard.rules.json existiert — unverändert gelassen`);
  }

  // 3) In settings.json registrieren (bestehende Settings mergen, nie zerstören)
  let settings = {};
  if (fs.existsSync(SETTINGS)) {
    try {
      settings = JSON.parse(fs.readFileSync(SETTINGS, "utf8"));
    } catch {
      console.log(`  ${c.red("✕")} .claude/settings.json ist kein valides JSON — bitte manuell prüfen.`);
      process.exit(1);
    }
  }
  settings.hooks = settings.hooks || {};

  const ensureHook = (event, command, matcher) => {
    settings.hooks[event] = settings.hooks[event] || [];
    const exists = JSON.stringify(settings.hooks[event]).includes("hooks/guard/");
    if (!exists) {
      settings.hooks[event].push({ matcher, hooks: [{ type: "command", command }] });
    }
  };
  ensureHook("PreToolUse", 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/pretool.js"', "*");
  ensureHook("UserPromptSubmit", 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/prompt.js"', undefined);
  ensureHook("PostToolUse", 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/posttool.js"', "Read|Bash");
  ensureHook("SessionStart", 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/session.js"', "startup|resume");

  fs.mkdirSync(CLAUDE_DIR, { recursive: true });
  fs.writeFileSync(SETTINGS, JSON.stringify(settings, null, 2));
  console.log(`  ${c.green("✓")} Hooks registriert → ${c.dim(".claude/settings.json")}`);

  // 4) .gitignore: die beiden maschinenlokalen Artefakte dürfen nie versioniert
  // werden — ein committetes Siegel würde bei jedem Klon eine falsche
  // "verifiziert ✓" erzeugen (host/root-Bindung in verify()/session.js schützt
  // zusätzlich, aber die Ursache gehört erst gar nicht ins Repo).
  ensureGitignore();

  // 5) Selbsttest
  const rules = loadRulesFile();
  const n = rules ? countRules(rules) : 0;
  console.log(`\n  ${c.green(c.bold(`✓ ${n} Regeln aktiv`))}`);
  console.log(c.dim("\n  Selbsttest läuft …"));

  // Die Installation beweist sich sofort selbst. Schlägt sie fehl, wird das
  // gemeldet — aber NICHT zurückgerollt: eine Teil-Installation ist besser als
  // gar keine, und der Nutzer braucht die Diagnose, nicht einen leeren Ordner.
  const code = verify();
  if (code !== 0) {
    console.log(c.dim("  Installation bleibt bestehen. Ursache oben beheben, dann: guard verify\n"));
    process.exit(1);
  }
  console.log(c.dim("  · Claude Code neu starten — guard meldet sich beim Start\n"));
}

function status() {
  const rules = loadRulesFile();
  if (!rules) {
    console.log(`\n  ${c.red("✕")} Kein guard.rules.json gefunden. Erst ${c.bold("guard init")} ausführen.\n`);
    process.exit(1);
  }
  console.log(c.bold("\n  @elevenworks/guard — status\n"));
  console.log(`  Modus:              ${rules.mode || "enforce"}`);
  console.log(`  Geschützte Pfade:   ${rules.blockedPaths?.length || 0}`);
  console.log(`  Kommando-Regeln:    ${rules.blockedCommands?.length || 0}`);
  console.log(`  PII-Muster:         ${rules.piiPatterns?.length || 0}`);
  console.log(`  Injection-Muster:   ${rules.injectionPatterns?.length || 0}`);
  console.log(`  ${c.green(c.bold(`✓ ${countRules(rules)} Regeln aktiv`))}`);
  const auditPath = path.join(CWD, rules.audit?.path || ".claude/guard-audit.jsonl");
  if (fs.existsSync(auditPath)) {
    const lines = fs.readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean);
    const blocked = lines.filter((l) => l.includes('"blocked"')).length;
    const would = lines.filter((l) => l.includes('"would-block"')).length;
    const suffix = would ? `, ${would} würde-blockiert (monitor)` : "";
    console.log(`  Audit-Events:       ${lines.length} gesamt, ${blocked} blockiert${suffix}`);
  }
  console.log("");
}

function report() {
  const rules = loadRulesFile();
  if (!rules) {
    console.log(`\n  ${c.red("✕")} Kein guard.rules.json gefunden. Erst ${c.bold("guard init")} ausführen.\n`);
    process.exit(1);
  }
  const auditPath = path.join(CWD, rules.audit?.path || ".claude/guard-audit.jsonl");
  let auditLines = [];
  if (fs.existsSync(auditPath)) {
    auditLines = fs.readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
  }
  const { buildReport } = require("../lib/report.js");
  const md = buildReport({ auditLines, rules, now: new Date().toISOString() });
  const out = path.join(CWD, "guard-report.md");
  fs.writeFileSync(out, md);
  console.log(md);
  console.log(c.dim(`\n  → auch geschrieben nach guard-report.md\n`));
}

function verify() {
  const { runVerify } = require("../lib/verify.js");
  const { writeSeal } = require("../hooks/lib.js");
  const pkg = JSON.parse(fs.readFileSync(path.join(PKG_ROOT, "package.json"), "utf8"));

  console.log(c.bold("\n  @elevenworks/guard — verify\n"));

  let r;
  try {
    r = runVerify({ cwd: CWD });
  } catch (e) {
    // z.B. mkdtempSync scheitert (Tmpdir nicht schreibbar) — eine ehrliche
    // Diagnose statt eines rohen Stack-Traces.
    console.log(`  ${c.red("✕")} Selbsttest konnte nicht laufen: ${e.message}`);
    console.log(c.dim("  Prüfe, ob das System-Tmpdir schreibbar ist, dann erneut: guard verify\n"));
    return 1;
  }

  for (const d of r.details) {
    const mark = !d.ok ? c.red("✕") : d.warn ? c.yellow("⚠") : c.green("✓");
    console.log(`  ${mark} ${d.label.padEnd(24)} ${c.dim(d.info)}`);
  }

  // r.fingerprint wurde bereits von runVerify() aus genau demselben Lauf
  // berechnet — ein zweites computeFingerprint(CWD) hier wäre nicht nur
  // doppelte Arbeit, sondern ein TOCTOU-Fenster: das Siegel könnte einen
  // Fingerabdruck festhalten, der vom tatsächlich getesteten Stand abweicht.
  writeSeal(CWD, {
    ts: new Date().toISOString(),
    guardVersion: pkg.version,
    mode: r.mode,
    fingerprint: r.fingerprint,
    ok: r.ok,
    // Maschinenlokaler Bezug (C1): ohne host/root wäre das Siegel
    // pfadunabhängig und würde bei jedem Klon fälschlich als "verifiziert"
    // gelten, sobald es versehentlich mitcommittet wird.
    host: os.hostname(),
    root: realRoot(CWD),
    checks: r.checks,
    // Deckungsgrad (A6): wie viele der konfigurierten Regeln wurden mit einem
    // Beweismuster tatsächlich zum Feuern gebracht — nicht nur "Regelwerk lädt".
    coverage: r.coverage,
  });

  if (r.ok) {
    const suffix = r.mode === "monitor" ? " (monitor-Modus: erkennt, blockt nicht)" : "";
    const { probed, total } = r.coverage;
    console.log(`\n  ${c.green(c.bold(`✓ ${probed}/${total} Regeln nachweislich scharf.` + suffix))}`);
    console.log(c.dim(`  Siegel: ${SEAL_REL}\n`));
    return 0;
  }
  console.log(`\n  ${c.red(c.bold("✕ Verifikation fehlgeschlagen."))}`);
  console.log(c.dim("  Ursache oben. Nach der Reparatur erneut: guard verify\n"));
  return 1;
}

const cmd = process.argv[2];
if (cmd === "init") init();
else if (cmd === "status") status();
else if (cmd === "report") report();
else if (cmd === "verify") process.exit(verify());
else {
  console.log(`\n  ${c.bold("@elevenworks/guard")} — Der Sicherheitsgurt für Claude Code\n`);
  console.log("  Befehle:");
  console.log("    guard init     Hooks + Regelwerk im aktuellen Projekt installieren");
  console.log("    guard status   Aktive Regeln und Audit-Zusammenfassung anzeigen");
  console.log("    guard report   Nachweis aus dem Audit-Log erzeugen");
  console.log("    guard verify   Selbsttest: ist guard wirklich verdrahtet und scharf?\n");
}
