"use strict";
// guard verify — der Selbsttest.
// Fährt den ECHTEN installierten Hook mit den ECHTEN Regeln, aber in einem
// Wegwerf-Verzeichnis: echter Test, sauberer Compliance-Trail.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { computeFingerprint, loadRules } = require("../hooks/lib.js");

const HOOK_EVENTS = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"];

// Ein Probe-Aufruf des echten Hooks in einem Wegwerf-cwd.
function probe(hookPath, rulesSrc, toolInput) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-probe-"));
  try {
    // Audit-Ziel neutralisieren: der Probe-Hook darf NIE ins echte Compliance-Log
    // schreiben (audit.path kann absolut sein), und seine Events müssen im
    // Wegwerf-Verzeichnis auffindbar bleiben.
    const r = JSON.parse(rulesSrc);
    r.audit = { ...(r.audit || {}), enabled: true, path: ".claude/guard-audit.jsonl" };
    fs.writeFileSync(path.join(dir, "guard.rules.json"), JSON.stringify(r));
    const res = spawnSync(process.execPath, [hookPath], {
      input: JSON.stringify({ ...toolInput, cwd: dir }),
      cwd: dir,
      encoding: "utf8",
    });
    const auditFile = path.join(dir, ".claude", "guard-audit.jsonl");
    const events = fs.existsSync(auditFile)
      ? fs.readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean)
      : [];
    return { exitCode: res.status, events };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function rulesSource(cwd) {
  for (const p of [path.join(cwd, "guard.rules.json"), path.join(cwd, ".claude", "guard.rules.json")]) {
    if (fs.existsSync(p)) return fs.readFileSync(p, "utf8");
  }
  return null;
}

// Echte Schreibprobe im Audit-Verzeichnis — ein reiner Rechte-Check (W_OK) kann
// lügen (read-only Mount, volle Platte, ACLs). Es wird KEIN Event geschrieben.
function auditWritable(cwd, rules) {
  const rel = rules?.audit?.path || ".claude/guard-audit.jsonl";
  const dir = path.dirname(path.isAbsolute(rel) ? rel : path.join(cwd, rel));
  const probeFile = path.join(dir, `.guard-write-probe-${process.pid}`);
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(probeFile, "probe");
    fs.rmSync(probeFile, { force: true });
    return true;
  } catch {
    try { fs.rmSync(probeFile, { force: true }); } catch {}
    return false;
  }
}

function runVerify({ cwd, hookPath }) {
  const root = cwd || process.cwd();
  const hook = hookPath || path.join(root, ".claude", "hooks", "guard", "pretool.js");
  const details = [];
  const checks = { registered: false, rulesLoaded: false, blocksSecret: false, allowsTemplate: false, auditWritable: false };

  // 1) Verdrahtung — computeFingerprint() liest/parst settings.json bereits und
  // scheitert identisch bei fehlender/kaputter Datei (fp.registered=false,
  // fp.events=[]); ein zweites Lesen wäre totes Code und eine TOCTOU-Quelle.
  const fp = computeFingerprint(root);
  const registered = new Set(fp.events);
  const missing = HOOK_EVENTS.filter((e) => !registered.has(e));
  checks.registered = fp.registered && missing.length === 0 && fs.existsSync(hook);
  details.push({
    key: "registered", ok: checks.registered, label: "Hooks registriert",
    info: checks.registered ? fp.events.join(", ") : (fp.registered ? `fehlt: ${missing.join(", ")}` : "keine guard-Hooks in .claude/settings.json"),
  });

  // 2) Regelwerk
  const rules = loadRules(root);
  const src = rulesSource(root);
  checks.rulesLoaded = Boolean(rules && src);
  const ruleCount = rules ? (rules.blockedPaths?.length || 0) + (rules.blockedCommands?.length || 0) + (rules.piiPatterns?.length || 0) + (rules.injectionPatterns?.length || 0) : 0;
  const mode = rules?.mode || "enforce";
  details.push({
    key: "rules", ok: checks.rulesLoaded, label: "Regelwerk geladen",
    info: checks.rulesLoaded ? `${ruleCount} Regeln · Modus: ${mode}` : "guard.rules.json fehlt oder ist ungültig",
  });

  if (!checks.rulesLoaded || !fs.existsSync(hook)) {
    return { ok: false, mode, ruleCount, fingerprint: fp.fingerprint, checks, details };
  }

  // 3) Blockt Secrets  (im monitor-Modus: erkennt sie — would-block, exit 0)
  const secret = probe(hook, src, { tool_name: "Read", tool_input: { file_path: ".env" } });
  const wanted = mode === "monitor" ? "would-block" : "blocked";
  const hit = secret.events.find((e) => e.event === wanted);
  checks.blocksSecret = mode === "monitor"
    ? secret.exitCode === 0 && Boolean(hit)
    : secret.exitCode === 2 && Boolean(hit);
  details.push({
    key: "blocksSecret", ok: checks.blocksSecret,
    label: mode === "monitor" ? "Erkennt Secrets" : "Blockt Secrets",
    info: checks.blocksSecret
      ? (mode === "monitor" ? `.env → würde blocken, lässt durch (${hit.ruleId})` : `.env → blockiert (${hit.ruleId})`)
      : `.env → erwartet ${wanted}, bekam exit ${secret.exitCode}`,
  });

  // 4) Blockt NICHT pauschal — die Präzision, die Entwickler überzeugt
  const template = probe(hook, src, { tool_name: "Read", tool_input: { file_path: ".env.example" } });
  checks.allowsTemplate = template.exitCode === 0 && !template.events.some((e) => e.event === "blocked" || e.event === "would-block");
  details.push({
    key: "allowsTemplate", ok: checks.allowsTemplate, label: "Blockt nicht pauschal",
    info: checks.allowsTemplate ? ".env.example → erlaubt" : ".env.example wurde fälschlich beanstandet",
  });

  // 5) Audit schreibbar
  checks.auditWritable = auditWritable(root, rules);
  details.push({
    key: "auditWritable", ok: checks.auditWritable, label: "Audit-Log schreibbar",
    info: rules?.audit?.path || ".claude/guard-audit.jsonl",
  });

  const ok = Object.values(checks).every(Boolean);
  return { ok, mode, ruleCount, fingerprint: fp.fingerprint, checks, details };
}

module.exports = { runVerify };
