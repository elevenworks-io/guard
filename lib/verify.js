"use strict";
// guard verify — der Selbsttest.
// Fährt den ECHTEN installierten Hook mit den ECHTEN Regeln, aber in einem
// Wegwerf-Verzeichnis: echter Test, sauberer Compliance-Trail.
//
// Beweist nicht nur "blockt .env / erlaubt .env.example" (das prüft nur den
// Pfad-Matcher), sondern JEDE einzelne konfigurierte Regel — Pfade, Kommandos,
// PII- und Injection-Muster — mit einem Beweismuster, das nachweislich zieht.
// Eine Regel ohne Muster wird als "ungeprüft" gemeldet, nie stillschweigend
// als Erfolg gezählt.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { computeFingerprint, loadRules, auditPathOf } = require("../hooks/lib.js");

const HOOK_EVENTS = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"];

// Geerntete Beweismuster (ruleId -> Sample), aus dem Testkorpus destilliert
// (tests/attacks/*.jsonl, siehe tests/samples.test.js für die Vollständigkeits-
// Garantie). Bewusst NICHT Teil von guard.rules.json — die Injection-Muster
// enthalten echte Prompt-Injection-Phrasen, die guards eigener PostToolUse-
// Detektor sonst bei jedem Lesen der Regel-Datei melden würde.
const SHIPPED_SAMPLES = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "templates", "guard.samples.json"), "utf8")
);

const RULE_CLASSES = [
  { key: "blockedPaths", kind: "path", label: "Pfad-Regeln" },
  { key: "blockedCommands", kind: "cmd", label: "Kommando-Regeln" },
  { key: "piiPatterns", kind: "pii", label: "PII-Muster" },
  { key: "injectionPatterns", kind: "inj", label: "Injection-Muster" },
];

// Spawnt den echten Hook einmal im gemeinsamen Wegwerf-cwd. Das Audit-Log
// darin wird VOR jedem Aufruf geleert — ein einziges Wegwerf-Verzeichnis für
// alle Proben (nicht 49 einzelne mkdtemp), aber jede Probe muss ihre eigenen
// Events trennscharf sehen können.
function spawnHook(dir, hookPath, toolInput) {
  const auditFile = path.join(dir, ".claude", "guard-audit.jsonl");
  fs.rmSync(auditFile, { force: true });
  const res = spawnSync(process.execPath, [hookPath], {
    input: JSON.stringify({ ...toolInput, cwd: dir }),
    cwd: dir,
    encoding: "utf8",
  });
  const events = fs.existsSync(auditFile)
    ? fs.readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean)
    : [];
  return { exitCode: res.status, events, stdout: res.stdout || "", stderr: res.stderr || "" };
}

// Regel-IDs stehen entweder top-level (pretool: e.ruleId) oder pro Fund
// (prompt/posttool: e.findings[].ruleId) — beide Formen berücksichtigen.
function ruleIdFired(events, id, wantedEvents) {
  return events.some((e) => {
    if (wantedEvents && !wantedEvents.includes(e.event)) return false;
    if (e.ruleId === id) return true;
    if (Array.isArray(e.findings) && e.findings.some((f) => f.ruleId === id)) return true;
    return false;
  });
}

// Probt EINE Regel mit ihrem Muster im gemeinsamen Wegwerf-cwd.
//   pretool (path/cmd): mode-abhängig — enforce erwartet "blocked" + exit 2,
//     monitor erwartet "would-block" + exit 0 (die Erkennung bleibt gleich,
//     nur die Durchsetzung schaltet um).
//   prompt/posttool (pii/inj): mode-unabhängig — sie warnen/erkennen immer.
function probeRule(dir, hooks, kind, id, sample, mode) {
  if (kind === "path") {
    const wanted = mode === "monitor" ? "would-block" : "blocked";
    const r = spawnHook(dir, hooks.pretool, { tool_name: "Read", tool_input: { file_path: sample } });
    return ruleIdFired(r.events, id, [wanted]);
  }
  if (kind === "cmd") {
    const wanted = mode === "monitor" ? "would-block" : "blocked";
    const r = spawnHook(dir, hooks.pretool, { tool_name: "Bash", tool_input: { command: sample } });
    return ruleIdFired(r.events, id, [wanted]);
  }
  if (kind === "pii") {
    const r = spawnHook(dir, hooks.prompt, { prompt: sample });
    return ruleIdFired(r.events, id, ["blocked", "warned"]);
  }
  if (kind === "inj") {
    const r = spawnHook(dir, hooks.posttool, {
      tool_name: "Read",
      tool_input: { file_path: "guard-verify-probe.md" },
      tool_response: sample,
    });
    return ruleIdFired(r.events, id, ["injection-detected"]);
  }
  return false;
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
  const dir = path.dirname(auditPathOf(cwd, rules));
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

function runVerify({ cwd, hookPath } = {}) {
  const root = cwd || process.cwd();
  const hook = hookPath || path.join(root, ".claude", "hooks", "guard", "pretool.js");
  const hookDir = path.dirname(hook);
  const hooks = { pretool: hook, posttool: path.join(hookDir, "posttool.js"), prompt: path.join(hookDir, "prompt.js") };
  const details = [];
  const checks = { registered: false, rulesLoaded: false, blocksSecret: false, allowsTemplate: false, auditWritable: false, auditDisabled: false };
  const emptyCoverage = { probed: 0, total: 0, unprobed: [] };

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
  // Minor: ein SKALARES Regelwerk (z.B. "hallo") ist typeof === "object" nur
  // für null/Array-Fälle nicht — Boolean(rules && src) allein ließ es früher
  // durch, und der Probe-Zugriff r.audit = … weiter unten warf dann eine
  // TypeError, die bin/cli.js fälschlich als Tmpdir-Fehler auswies.
  const rulesIsObject = rules !== null && typeof rules === "object" && !Array.isArray(rules);
  checks.rulesLoaded = Boolean(rulesIsObject && src);
  const ruleCount = checks.rulesLoaded ? (rules.blockedPaths?.length || 0) + (rules.blockedCommands?.length || 0) + (rules.piiPatterns?.length || 0) + (rules.injectionPatterns?.length || 0) : 0;
  const mode = checks.rulesLoaded ? (rules.mode || "enforce") : "enforce";
  details.push({
    key: "rules", ok: checks.rulesLoaded, label: "Regelwerk geladen",
    info: checks.rulesLoaded ? `${ruleCount} Regeln · Modus: ${mode}` : "guard.rules.json fehlt oder ist ungültig",
  });

  if (!checks.rulesLoaded || !fs.existsSync(hook)) {
    return { ok: false, mode, ruleCount, fingerprint: fp.fingerprint, checks, details, coverage: emptyCoverage, auditDisabled: false };
  }

  // Ein einziges Wegwerf-cwd für ALLE Proben unten (nicht eins pro Regel).
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-probe-"));
  try {
    // Audit-Ziel neutralisieren: der Probe-Hook darf NIE ins echte Compliance-Log
    // schreiben (audit.path kann absolut sein), und seine Events müssen im
    // Wegwerf-Verzeichnis auffindbar bleiben. Gilt für JEDE Probe unten.
    const rNeutral = JSON.parse(src);
    rNeutral.audit = { ...(rNeutral.audit || {}), enabled: true, path: ".claude/guard-audit.jsonl" };
    fs.writeFileSync(path.join(dir, "guard.rules.json"), JSON.stringify(rNeutral));

    // 3) Jede Regel einzeln beweisen — Kern dieser Änderung. Vorher wurden
    // nur zwei Fälle geprüft (.env blockt, .env.example nicht); jetzt jede der
    // 4 Regelklassen, Muster-für-Muster.
    let probedTotal = 0;
    let ruleTotal = 0;
    const unprobed = [];
    let anyFailure = false;
    const probedIds = new Set();

    for (const cls of RULE_CLASSES) {
      const arr = rules[cls.key] || [];
      let classProbed = 0;
      const classFailures = [];
      for (const rule of arr) {
        const sample = rule.sample !== undefined ? rule.sample : SHIPPED_SAMPLES[rule.id];
        if (sample === undefined) { unprobed.push(rule.id); continue; }
        const fired = probeRule(dir, hooks, cls.kind, rule.id, sample, mode);
        if (fired) { classProbed++; probedIds.add(rule.id); } else { classFailures.push(rule.id); }
      }
      ruleTotal += arr.length;
      probedTotal += classProbed;
      if (classFailures.length) anyFailure = true;
      details.push({
        key: `class:${cls.key}`, ok: classFailures.length === 0, label: cls.label,
        info: arr.length === 0 ? "0 Regeln konfiguriert" : `${classProbed}/${arr.length} probiert`,
      });
      for (const id of classFailures) {
        details.push({
          key: `fail:${id}`, ok: false, label: `Regel ${id}`,
          info: `Regel ${id} greift nicht auf ihr Testmuster — Muster geändert? Eigenes "sample" in guard.rules.json setzen.`,
        });
      }
    }

    if (unprobed.length) {
      details.push({
        key: "unprobed", ok: true, warn: true,
        label: `${unprobed.length} eigene Regel${unprobed.length === 1 ? "" : "n"} ohne Testmuster`,
        info: `nicht probiert: ${unprobed.join(", ")}`,
      });
    }

    // 4) Blockt Secrets — Positivkontrolle unabhängig davon, ob "path.dotenv"
    // überhaupt konfiguriert ist. Wird aus derselben Probenrunde abgeleitet
    // (kein zusätzlicher Spawn nötig, path.dotenv ist Teil der Pfad-Regeln).
    checks.blocksSecret = probedIds.has("path.dotenv");

    // 5) Blockt NICHT pauschal — die Präzision, die Entwickler überzeugt
    const template = spawnHook(dir, hooks.pretool, { tool_name: "Read", tool_input: { file_path: ".env.example" } });
    checks.allowsTemplate = template.exitCode === 0 && !template.events.some((e) => e.event === "blocked" || e.event === "would-block");
    details.push({
      key: "allowsTemplate", ok: checks.allowsTemplate, label: "Blockt nicht pauschal",
      info: checks.allowsTemplate ? ".env.example → erlaubt" : ".env.example wurde fälschlich beanstandet",
    });

    // 6) Audit schreibbar — im ECHTEN Projekt-cwd, nicht im Wegwerf-Verzeichnis.
    // I2: audit.enabled:false bedeutet, dass audit() ein No-Op ist — es wird
    // NIE ein Compliance-Log geschrieben, egal wie schreibbar das Verzeichnis
    // wäre. Das früher grüne "✓ Audit-Log schreibbar" in dieser Konfiguration
    // war eine stille Falschbehauptung (Beweis-Artefakt existiert schlicht
    // nicht). Ehrlich als Warnung melden, nicht als harten Fehlschlag — das
    // Deaktivieren ist eine legitime Nutzerentscheidung.
    const auditDisabled = rules?.audit?.enabled === false;
    checks.auditDisabled = auditDisabled;
    if (auditDisabled) {
      checks.auditWritable = true; // keine Schreibbarkeits-Bedingung, wenn ohnehin nie geschrieben wird
      details.push({
        key: "auditWritable", ok: true, warn: true, label: "Audit-Log deaktiviert",
        info: "audit.enabled:false — es wird KEIN Compliance-Log geschrieben",
      });
    } else {
      checks.auditWritable = auditWritable(root, rules);
      details.push({
        key: "auditWritable", ok: checks.auditWritable, label: "Audit-Log schreibbar",
        info: rules?.audit?.path || ".claude/guard-audit.jsonl",
      });
    }

    const ok = checks.registered && checks.rulesLoaded && checks.blocksSecret && checks.allowsTemplate && checks.auditWritable && !anyFailure;
    const coverage = { probed: probedTotal, total: ruleTotal, unprobed };
    return { ok, mode, ruleCount, fingerprint: fp.fingerprint, checks, details, coverage, auditDisabled };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

module.exports = { runVerify };
