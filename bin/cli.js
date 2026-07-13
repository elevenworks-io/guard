#!/usr/bin/env node
// @elevenworks/guard — CLI
// Befehle: init (Hooks im Projekt installieren), status (aktive Regeln zeigen)
"use strict";
const fs = require("fs");
const path = require("path");

const { SEAL_REL } = require("../hooks/lib.js");

const PKG_ROOT = path.join(__dirname, "..");
const CWD = process.cwd();
const CLAUDE_DIR = path.join(CWD, ".claude");
const HOOKS_DIR = path.join(CLAUDE_DIR, "hooks", "guard");
const SETTINGS = path.join(CLAUDE_DIR, "settings.json");
const RULES_TARGET = path.join(CWD, "guard.rules.json");

const c = {
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
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

function loadRulesFile() {
  for (const p of [RULES_TARGET, path.join(CLAUDE_DIR, "guard.rules.json")]) {
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
  }
  return null;
}

function init() {
  console.log(c.bold("\n  @elevenworks/guard — init\n"));

  // 1) Hook-Scripts kopieren
  fs.mkdirSync(HOOKS_DIR, { recursive: true });
  for (const f of ["lib.js", "pretool.js", "prompt.js", "posttool.js"]) {
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

  const ensureHook = (event, command) => {
    settings.hooks[event] = settings.hooks[event] || [];
    const exists = JSON.stringify(settings.hooks[event]).includes("hooks/guard/");
    if (!exists) {
      settings.hooks[event].push({
        matcher: event === "PreToolUse" ? "*" : event === "PostToolUse" ? "Read|Bash" : undefined,
        hooks: [{ type: "command", command }],
      });
    }
  };
  ensureHook("PreToolUse", 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/pretool.js"');
  ensureHook("UserPromptSubmit", 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/prompt.js"');
  ensureHook("PostToolUse", 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/posttool.js"');

  fs.mkdirSync(CLAUDE_DIR, { recursive: true });
  fs.writeFileSync(SETTINGS, JSON.stringify(settings, null, 2));
  console.log(`  ${c.green("✓")} Hooks registriert → ${c.dim(".claude/settings.json")}`);

  // 4) Audit-Log vorbereiten + .gitignore-Hinweis
  const rules = loadRulesFile();
  const n = rules ? countRules(rules) : 0;
  console.log(`\n  ${c.green(c.bold(`✓ ${n} Regeln aktiv`))}`);
  console.log(c.dim("\n  Nächste Schritte:"));
  console.log(c.dim("  · guard.rules.json ans Projekt anpassen"));
  console.log(c.dim("  · .claude/guard-audit.jsonl in .gitignore aufnehmen"));
  console.log(c.dim("  · Claude Code neu starten, damit Hooks greifen\n"));
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
  const { computeFingerprint, writeSeal } = require("../hooks/lib.js");
  const pkg = JSON.parse(fs.readFileSync(path.join(PKG_ROOT, "package.json"), "utf8"));

  console.log(c.bold("\n  @elevenworks/guard — verify\n"));
  const r = runVerify({ cwd: CWD });
  for (const d of r.details) {
    const mark = d.ok ? c.green("✓") : c.red("✕");
    console.log(`  ${mark} ${d.label.padEnd(24)} ${c.dim(d.info)}`);
  }

  const fp = computeFingerprint(CWD);
  writeSeal(CWD, {
    ts: new Date().toISOString(),
    guardVersion: pkg.version,
    mode: r.mode,
    fingerprint: fp.fingerprint,
    ok: r.ok,
    checks: r.checks,
  });

  if (r.ok) {
    const suffix = r.mode === "monitor" ? " (monitor-Modus: erkennt, blockt nicht)" : "";
    console.log(`\n  ${c.green(c.bold("✓ guard ist verifiziert scharf." + suffix))}`);
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
