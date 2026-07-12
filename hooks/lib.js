// @elevenworks/guard — shared hook library
// Hooks kommunizieren mit Claude Code über stdin (JSON) und Exit-Codes:
//   exit 0 = erlaubt, exit 2 = blockiert (stderr wird Claude als Begründung gezeigt)
"use strict";
const fs = require("fs");
const path = require("path");

function readStdin() {
  try {
    return JSON.parse(fs.readFileSync(0, "utf8"));
  } catch {
    return null;
  }
}

function loadRules(cwd) {
  const candidates = [
    path.join(cwd || process.cwd(), "guard.rules.json"),
    path.join(cwd || process.cwd(), ".claude", "guard.rules.json"),
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
    } catch (e) {
      process.stderr.write(`[guard] Regel-Datei fehlerhaft: ${p} — ${e.message}\n`);
    }
  }
  return null;
}

// Glob-Matcher: **/ matcht null oder mehr Pfadsegmente (inkl. keins),
// ** matcht beliebig, * bleibt innerhalb eines Segments.
function globToRegex(glob) {
  const esc = glob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*\//g, "§§DSLASH§§")
    .replace(/\*\*/g, "§§DOUBLE§§")
    .replace(/\*/g, "[^/]*")
    .replace(/§§DSLASH§§/g, "(?:.*/)?")
    .replace(/§§DOUBLE§§/g, ".*");
  return new RegExp("(^|/)" + esc + "$");
}

function pathBlocked(filePath, rules) {
  if (!filePath || !rules?.blockedPaths) return null;
  const norm = String(filePath).replace(/\\/g, "/");
  // Safe template files (.env.example, *.sample, …) are explicitly allowed even
  // when they match a blocked pattern — guard itself recommends .env.example.
  for (const glob of rules.allowPaths || []) {
    if (globToRegex(glob).test(norm)) return null;
  }
  for (const rule of rules.blockedPaths) {
    if (globToRegex(rule.glob).test(norm)) return rule; // { id, glob }
  }
  return null;
}

function commandTouchesBlockedPath(command, rules) {
  if (!command || !rules?.blockedPaths) return null;
  const tokens = String(command).split(/[\s'"()\[\]{}<>,;:|&$`+=]+/).filter(Boolean);
  for (const tok of tokens) {
    const rule = pathBlocked(tok, rules);
    if (rule) return { rule, token: tok };
  }
  return null;
}

function commandBlocked(command, rules) {
  if (!command || !rules?.blockedCommands) return null;
  for (const rule of rules.blockedCommands) {
    try {
      const re = new RegExp(rule.pattern, rule.flags || "");
      if (re.test(command)) return rule;
    } catch { /* fehlerhafte Regel überspringen */ }
  }
  return null;
}

function scanPII(text, rules) {
  const hits = [];
  if (!text || !rules?.piiPatterns) return hits;
  for (const p of rules.piiPatterns) {
    try {
      const re = new RegExp(p.pattern, (p.flags || "") + "g");
      const matches = text.match(re) || [];
      for (const m of matches) {
        if (p.allowDomains && p.allowDomains.some((d) => m.toLowerCase().endsWith("@" + d) || m.toLowerCase().endsWith("." + d))) continue;
        hits.push({ ruleId: p.id, name: p.name, action: p.action || "warn", sample: mask(m) });
      }
    } catch { /* fehlerhafte Regel überspringen */ }
  }
  return hits;
}

function scanInjection(text, rules) {
  const hits = [];
  if (!text || !rules?.injectionPatterns) return hits;
  for (const p of rules.injectionPatterns) {
    try {
      if (new RegExp(p.pattern, p.flags || "").test(text)) hits.push({ ruleId: p.id, name: p.id });
    } catch { /* fehlerhafte Regel überspringen */ }
  }
  return hits;
}

function mask(s) {
  if (s.length <= 6) return "***";
  return s.slice(0, 3) + "…" + s.slice(-2) + ` (${s.length} Zeichen)`;
}

function audit(event, rules, cwd) {
  try {
    if (rules?.audit?.enabled === false) return;
    const rel = rules?.audit?.path || ".claude/guard-audit.jsonl";
    const p = path.isAbsolute(rel) ? rel : path.join(cwd || process.cwd(), rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.appendFileSync(p, JSON.stringify({ ts: new Date().toISOString(), ...event }) + "\n");
  } catch { /* Audit darf den Workflow nie crashen */ }
}

module.exports = { readStdin, loadRules, pathBlocked, commandBlocked, commandTouchesBlockedPath, scanPII, scanInjection, audit };
