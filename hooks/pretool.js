#!/usr/bin/env node
// @elevenworks/guard — PreToolUse Hook
// Blockiert (enforce) bzw. loggt nur (monitor): Secret-Pfade, gefährliche Shell-Kommandos.
"use strict";
const { readStdin, loadRules, pathBlocked, commandBlocked, commandTouchesBlockedPath, audit } = require("./lib.js");

const input = readStdin();
if (!input) process.exit(0); // fail-open bei kaputtem Input (v0.1-Entscheidung, siehe README)

const cwd = input.cwd || process.cwd();
const rules = loadRules(cwd);
if (!rules) process.exit(0);

const tool = input.tool_name || "";
const ti = input.tool_input || {};

// Zentrale Durchsetzungs-Entscheidung.
//   enforce (Default): Audit "blocked" + stderr-Begründung + exit 2 (unverändertes Verhalten).
//   monitor:           Audit "would-block" + kurzer stdout-Hinweis + exit 0 (durchlassen).
// enforceMsg wird per Corpus reasonSnapshot geprüft — Wortlaut nicht verändern.
function decide(auditEvent, enforceMsg, monitorNote) {
  if ((rules.mode || "enforce") === "monitor") {
    audit({ ...auditEvent, event: "would-block" }, rules, cwd);
    process.stdout.write(JSON.stringify({
      systemMessage: `[guard] ⚠️ monitor-Modus: würde blockieren (${monitorNote}) — durchgelassen, protokolliert.`,
    }));
    process.exit(0);
  }
  audit({ ...auditEvent, event: "blocked" }, rules, cwd);
  process.stderr.write(enforceMsg);
  process.exit(2);
}

// 1) Datei-Zugriffe prüfen (Read, Edit, Write, etc.)
const fileTarget = ti.file_path || ti.path || ti.notebook_path || null;
if (fileTarget) {
  const hit = pathBlocked(fileTarget, rules);
  if (hit) decide(
    { type: "path", tool, target: fileTarget, ruleId: hit.id, rule: hit.glob },
    `[guard] Zugriff blockiert: "${fileTarget}" ist als Secret/geschützter Pfad klassifiziert (Regel: ${hit.id}). ` +
      `Nutze .env.example oder frage den Menschen nach einer freigegebenen Alternative.`,
    `${fileTarget} — ${hit.id}`
  );
}

// 2) Bash-Kommandos prüfen
if (tool === "Bash" && ti.command) {
  // 2a) Kommando-Denylist
  const cmdHit = commandBlocked(ti.command, rules);
  if (cmdHit) decide(
    { type: "command", tool, command: ti.command.slice(0, 300), ruleId: cmdHit.id, rule: cmdHit.pattern },
    `[guard] Kommando blockiert: ${cmdHit.reason}`,
    `${cmdHit.id}`
  );
  // 2b) Versucht das Kommando, einen geschützten Pfad zu lesen?
  const pathHit = commandTouchesBlockedPath(ti.command, rules);
  if (pathHit) decide(
    { type: "command-path", tool, command: ti.command.slice(0, 300), ruleId: pathHit.rule.id, rule: pathHit.rule.glob },
    `[guard] Kommando blockiert: greift auf geschützten Pfad zu (${pathHit.rule.glob}).`,
    `${pathHit.rule.glob}`
  );
}

audit({ event: "allowed", tool, target: fileTarget || (ti.command ? ti.command.slice(0, 200) : null) }, rules, cwd);
process.exit(0);
