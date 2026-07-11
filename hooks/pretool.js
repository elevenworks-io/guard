#!/usr/bin/env node
// @elevenworks/guard — PreToolUse Hook
// Blockiert: Zugriff auf Secret-Dateien, gefährliche Shell-Kommandos.
"use strict";
const { readStdin, loadRules, pathBlocked, commandBlocked, commandTouchesBlockedPath, audit } = require("./lib.js");

const input = readStdin();
if (!input) process.exit(0); // fail-open bei kaputtem Input (v0.1-Entscheidung, siehe README)

const cwd = input.cwd || process.cwd();
const rules = loadRules(cwd);
if (!rules) process.exit(0);

const tool = input.tool_name || "";
const ti = input.tool_input || {};

// 1) Datei-Zugriffe prüfen (Read, Edit, Write, etc.)
const fileTarget = ti.file_path || ti.path || ti.notebook_path || null;
if (fileTarget) {
  const hit = pathBlocked(fileTarget, rules);
  if (hit) {
    audit({ event: "blocked", type: "path", tool, target: fileTarget, ruleId: hit.id, rule: hit.glob }, rules, cwd);
    process.stderr.write(
      `[guard] Zugriff blockiert: "${fileTarget}" ist als Secret/geschützter Pfad klassifiziert (Regel: ${hit.id}). ` +
      `Nutze .env.example oder frage den Menschen nach einer freigegebenen Alternative.`
    );
    process.exit(2);
  }
}

// 2) Bash-Kommandos prüfen
if (tool === "Bash" && ti.command) {
  // 2a) Kommando-Denylist
  const cmdHit = commandBlocked(ti.command, rules);
  if (cmdHit) {
    audit({ event: "blocked", type: "command", tool, command: ti.command.slice(0, 300), ruleId: cmdHit.id, rule: cmdHit.pattern }, rules, cwd);
    process.stderr.write(`[guard] Kommando blockiert: ${cmdHit.reason}`);
    process.exit(2);
  }
  // 2b) Versucht das Kommando, einen geschützten Pfad zu lesen?
  const pathHit = commandTouchesBlockedPath(ti.command, rules);
  if (pathHit) {
    audit({ event: "blocked", type: "command-path", tool, command: ti.command.slice(0, 300), ruleId: pathHit.rule.id, rule: pathHit.rule.glob }, rules, cwd);
    process.stderr.write(`[guard] Kommando blockiert: greift auf geschützten Pfad zu (${pathHit.rule.glob}).`);
    process.exit(2);
  }
}

audit({ event: "allowed", tool, target: fileTarget || (ti.command ? ti.command.slice(0, 200) : null) }, rules, cwd);
process.exit(0);
