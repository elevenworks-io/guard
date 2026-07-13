// @elevenworks/guard — shared hook library
// Hooks kommunizieren mit Claude Code über stdin (JSON) und Exit-Codes:
//   exit 0 = erlaubt, exit 2 = blockiert (stderr wird Claude als Begründung gezeigt)
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

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

const SEAL_REL = ".claude/guard-verified.json";
const HOOK_FILES = ["lib.js", "pretool.js", "posttool.js", "prompt.js", "session.js"];

// Nur die guard-relevanten Hook-Registrierungen aus settings.json — fremde
// Einträge (andere Tools, env-Vars) dürfen das Siegel nicht invalidieren.
function guardHookEntries(settings) {
  const out = [];
  for (const [event, arr] of Object.entries(settings?.hooks || {})) {
    for (const entry of arr || []) {
      const commands = (entry.hooks || [])
        .map((h) => h && h.command)
        .filter((c) => typeof c === "string" && c.includes("hooks/guard/"))
        .sort();
      if (commands.length) out.push({ event, matcher: entry.matcher ?? null, commands });
    }
  }
  out.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return out;
}

// Fingerabdruck über Verdrahtung + Regeln + Hook-Skripte.
// Ohne guard-Registrierung: registered=false (defensiv — nie stiller Erfolg).
function computeFingerprint(cwd) {
  const root = cwd || process.cwd();
  let entries = [];
  try {
    entries = guardHookEntries(JSON.parse(fs.readFileSync(path.join(root, ".claude", "settings.json"), "utf8")));
  } catch { /* keine/kaputte settings.json → nicht registriert */ }
  if (entries.length === 0) return { fingerprint: null, registered: false, events: [] };

  const h = crypto.createHash("sha256");
  h.update("wiring:" + JSON.stringify(entries) + "\n");
  let rulesSrc = "<fehlt>";
  for (const p of [path.join(root, "guard.rules.json"), path.join(root, ".claude", "guard.rules.json")]) {
    if (fs.existsSync(p)) { rulesSrc = fs.readFileSync(p, "utf8"); break; }
  }
  h.update("rules:" + rulesSrc + "\n");
  for (const f of HOOK_FILES) {
    const p = path.join(root, ".claude", "hooks", "guard", f);
    h.update(`hook:${f}:` + (fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "<fehlt>") + "\n");
  }
  return { fingerprint: "sha256:" + h.digest("hex"), registered: true, events: entries.map((e) => e.event) };
}

function readSeal(cwd) {
  try {
    return JSON.parse(fs.readFileSync(path.join(cwd || process.cwd(), SEAL_REL), "utf8"));
  } catch {
    return null;
  }
}

function writeSeal(cwd, seal) {
  const p = path.join(cwd || process.cwd(), SEAL_REL);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(seal, null, 2) + "\n");
}

module.exports = { readStdin, loadRules, pathBlocked, commandBlocked, commandTouchesBlockedPath, scanPII, scanInjection, audit, computeFingerprint, guardHookEntries, readSeal, writeSeal, SEAL_REL };
