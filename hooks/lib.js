// @elevenworks/guard — shared hook library
// Hooks kommunizieren mit Claude Code über stdin (JSON) und Exit-Codes:
//   exit 0 = erlaubt, exit 2 = blockiert (stderr wird Claude als Begründung gezeigt)
"use strict";
const fs = require("fs");
const os = require("os");
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

// Einzige Quelle der Wahrheit für "wo liegt das Audit-Log wirklich" — ein
// absoluter audit.path muss unverändert bleiben (I3: status()/report() haben
// das früher ignoriert und still 0 Events gezählt, obwohl echte Events an
// einem absoluten Pfad lagen). audit(), status(), report() und verify()
// MÜSSEN alle über diesen Helper gehen, sonst können sie wieder auseinanderdriften.
function auditPathOf(cwd, rules) {
  const rel = rules?.audit?.path || ".claude/guard-audit.jsonl";
  return path.isAbsolute(rel) ? rel : path.join(cwd || process.cwd(), rel);
}

function audit(event, rules, cwd) {
  try {
    if (rules?.audit?.enabled === false) return;
    const p = auditPathOf(cwd, rules);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.appendFileSync(p, JSON.stringify({ ts: new Date().toISOString(), ...event }) + "\n");
  } catch { /* Audit darf den Workflow nie crashen */ }
}

const SEAL_REL = ".claude/guard-verified.json";
const HOOK_FILES = ["lib.js", "pretool.js", "posttool.js", "prompt.js", "session.js"];

// Realpath-normalisierte Projekt-Root — macOS' /tmp → /private/tmp (Symlink)
// erzeugt sonst falsche Negative bei String-Vergleichen zwischen Schreiber
// (cli.js) und Leser (session.js). Beide MÜSSEN denselben Helper nutzen,
// sonst können sie auseinanderdriften.
function realRoot(cwd) {
  const root = cwd || process.cwd();
  try {
    return fs.realpathSync(root);
  } catch {
    return root;
  }
}

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
//
// M4: opts.rulesSrc lässt einen Aufrufer, der den Regel-Inhalt bereits selbst
// gelesen hat (z.B. lib/verify.js), diesen Lesevorgang hier NICHT wiederholen
// — ein zweites unabhängiges fs.readFileSync() wäre ein TOCTOU-Fenster (eine
// Editierung zwischen den beiden Lesevorgängen würde einen Fingerabdruck von
// Zustand A mit einer Probe von Zustand B versiegeln). Ohne opts.rulesSrc:
// unverändertes Verhalten (selbst von der Platte lesen).
function computeFingerprint(cwd, opts) {
  const root = cwd || process.cwd();
  let entries = [];
  try {
    entries = guardHookEntries(JSON.parse(fs.readFileSync(path.join(root, ".claude", "settings.json"), "utf8")));
  } catch { /* keine/kaputte settings.json → nicht registriert */ }
  if (entries.length === 0) return { fingerprint: null, registered: false, events: [] };

  const h = crypto.createHash("sha256");
  h.update("wiring:" + JSON.stringify(entries) + "\n");
  let rulesSrc = "<fehlt>";
  if (opts && typeof opts.rulesSrc === "string") {
    rulesSrc = opts.rulesSrc;
  } else {
    for (const p of [path.join(root, "guard.rules.json"), path.join(root, ".claude", "guard.rules.json")]) {
      if (fs.existsSync(p)) { rulesSrc = fs.readFileSync(p, "utf8"); break; }
    }
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

// Wo der maschinenlokale Identifier liegt — AUSSERHALB des Repos, respektiert
// XDG_CONFIG_HOME, fällt sonst auf ~/.config zurück.
function machineIdDir() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  return path.join(base, "elevenworks-guard");
}

// I1: host+root sind in Devcontainern/CI oft deterministisch identisch auf
// jeder Maschine (Hostname = Servicename, Arbeitsverzeichnis = /workspaces/…
// oder /app) — ein committetes/geklontes Siegel würde dort trotz host+root-
// Bindung überall als "verifiziert" gelten. Ein zufälliger, AUSSERHALB des
// Repos persistierter Identifier schließt genau diese Lücke.
//
// Darf NIE werfen (fail-open-Anspruch des gesamten Hooks) — ist das
// Config-Verzeichnis nicht schreibbar, wird null zurückgegeben. Aufrufer
// MÜSSEN null strikt als "kein Match" behandeln (null !== ein Siegel ohne
// installId, sonst würde ein defektes machineId() versehentlich jedes
// installId-lose Siegel validieren).
function machineId() {
  try {
    const dir = machineIdDir();
    const file = path.join(dir, "machine-id");
    try {
      const existing = fs.readFileSync(file, "utf8").trim();
      if (existing) return existing;
    } catch { /* noch keine Datei an diesem Pfad — unten Fallback/Neuanlage */ }

    // I3: Env-Divergenz. Ist XDG_CONFIG_HOME gesetzt, aber dort liegt noch
    // keine ID, zuerst am HOME-Fallback-Pfad nachsehen, BEVOR eine neue ID
    // angelegt wird. Ohne das: eine Shell mit gesetztem XDG_CONFIG_HOME (z.B.
    // "guard verify" manuell ausgeführt) legt eine ID unter XDG an, während
    // der von Claude Code gespawnte Hook (ohne dieses env) weiterhin die
    // HOME-ID sieht — zwei IDs, das Siegel passt nie zusammen, das Banner
    // bleibt für immer bei "nicht verifiziert", ohne dass der Nutzer je
    // erfährt, warum. Reines Lesen — schreibt NIE in den HOME-Fallback.
    if (process.env.XDG_CONFIG_HOME) {
      try {
        const homeFile = path.join(os.homedir(), ".config", "elevenworks-guard", "machine-id");
        const existingHome = fs.readFileSync(homeFile, "utf8").trim();
        if (existingHome) return existingHome;
      } catch { /* auch dort keine ID — unten am XDG-Pfad neu anlegen */ }
    }

    const id = crypto.randomBytes(16).toString("hex");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, id + "\n");
    return id;
  } catch {
    return null;
  }
}

module.exports = { readStdin, loadRules, pathBlocked, commandBlocked, commandTouchesBlockedPath, scanPII, scanInjection, audit, auditPathOf, computeFingerprint, guardHookEntries, readSeal, writeSeal, SEAL_REL, HOOK_FILES, realRoot, machineId };
