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
const { computeFingerprint, auditPathOf, guardHookEntries, resolveDisableAllHooks } = require("../hooks/lib.js");

const HOOK_EVENTS = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"];

// A10: die kanonische Verdrahtung, die `guard init` erzeugt — EINZIGE Quelle
// der Wahrheit dafür, welches Skript und welcher Matcher pro Event ERWARTET
// wird. `verify` testete bisher nur, ob die Hook-SKRIPTE korrekt funktionieren
// (per Konvention gespawnt) — nie, ob Claude Code sie über settings.json
// überhaupt (und für die richtigen Tools) AUFRUFT. Ein registriertes Kommando,
// das auf ein anderes Skript im selben Verzeichnis zeigt (Sabotage, Tippfehler,
// Merge-Artefakt), oder ein zu eng gefasster Matcher (PreToolUse: "Read" statt
// "*") lässt Claude Code den Hook nie/nicht-für-alle-Tools aufrufen — beides
// bisher voll grün, weil verify() immer den KONVENTIONELLEN Pfad probte, nie
// den tatsächlich VERDRAHTETEN.
const CANONICAL_WIRING = {
  PreToolUse: { file: "pretool.js", matcher: "*" },
  PostToolUse: { file: "posttool.js", matcher: "Read|Bash" },
  UserPromptSubmit: { file: "prompt.js", matcher: null },
  SessionStart: { file: "session.js", matcher: "startup|resume" },
};

const MATCHER_HINTS = {
  PreToolUse: "Bash-Kommandos werden NICHT geprüft",
  PostToolUse: "Read/Bash-Ergebnisse werden NICHT geprüft",
  UserPromptSubmit: "Prompts werden NICHT für alle Eingaben geprüft",
  SessionStart: "der Verifizierungs-Banner erscheint NICHT zuverlässig beim Start",
};

// Löst `node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/<name>.js"` (so schreibt
// es `init`) auf einen absoluten Pfad auf — toleriert An-/Abwesenheit von
// Anführungszeichen und beide Slash-Richtungen. Liefert null, wenn das
// Kommando $CLAUDE_PROJECT_DIR gar nicht referenziert (dann ist es keine
// erkennbare guard-Verdrahtung, sondern etwas anderes/Fremdes).
function resolveWiredScript(command, root) {
  if (typeof command !== "string") return null;
  const m = command.match(/\$CLAUDE_PROJECT_DIR([^\s"']+)/);
  if (!m || !m[1]) return null;
  const rel = m[1].replace(/\\/g, "/").replace(/^\/+/, "");
  if (!rel) return null;
  return path.resolve(root, rel);
}

function matcherProblem(event, actual, expected) {
  const shown = actual === null || actual === undefined ? "(kein Matcher)" : `"${actual}"`;
  const expectedShown = expected === null ? "keinen Matcher (Feld weglassen)" : `"${expected}"`;
  return `${event}-Matcher ist ${shown} — ${MATCHER_HINTS[event]}. Erwartet: ${expectedShown}.`;
}

// Die eigentliche Verdrahtungsprüfung: für jedes der vier guard-Events wird
// geprüft, dass GENAU EIN guard-Kommando registriert ist, dass es auf das
// ERWARTETE Skript zeigt (nicht irgendein anderes im selben Verzeichnis), dass
// dieses Skript existiert, UND dass der Matcher exakt der geforderte ist. Ein
// Fehlschlag hier ist ein harter Fehlschlag — er bedeutet, Claude Code ruft
// guard für (mindestens) einen Tool-Typ oder ein Event gar nicht auf.
//
// Liefert zusätzlich, best-effort, den aufgelösten Pfad pro Event (auch wenn
// er NICHT dem Kanon entspricht oder nicht existiert) — verify() probt genau
// DIESEN Pfad weiter unten, nicht mehr den konventionellen. Das macht die
// Garantie strukturell: was tatsächlich verdrahtet ist, wird getestet, nicht
// was per Konvention dort erwartet würde.
function checkWiring(root) {
  let settings = null;
  try {
    settings = JSON.parse(fs.readFileSync(path.join(root, ".claude", "settings.json"), "utf8"));
  } catch { /* keine/kaputte settings.json — jedes Event unten fällt auf "nicht registriert" */ }
  const entries = settings ? guardHookEntries(settings) : [];

  const problems = [];
  const perEvent = {};

  // disableAllHooks: der eine Schalter, der laut offizieller Claude-Code-
  // Doku ALLE Hooks abschaltet — auch PreToolUse, das sonst selbst
  // bypassPermissions/--dangerously-skip-permissions ignoriert. Ohne diesen
  // Check probt `verify` weiterhin die Hook-SKRIPTE direkt (per CLI, nicht
  // über Claude Code) und meldet fälschlich grün, obwohl Claude Code die
  // Hooks in einer echten Session nie aufruft — ein Siegel für einen Guard,
  // der nicht läuft. Harter Fehlschlag, unabhängig vom Rest der Verdrahtung.
  //
  // KRITISCH: über ALLE Scopes auflösen, nicht nur die Projekt-Datei. Claude
  // Code merged managed → local → project → user; ein `disableAllHooks: true`
  // in .claude/settings.local.json (höhere Präzedenz, meist gitignored) oder
  // in ~/.claude/settings.json (User-Scope, greift wenn Projekt schweigt)
  // schaltet guard global ab. Die Registrierung selbst bleibt Projekt-lokal
  // korrekt (Hooks mergen additiv, kein anderer Scope entfernt sie) — nur
  // dieser eine Kill-Switch braucht die Scope-übergreifende Auflösung.
  const dis = resolveDisableAllHooks(root);
  if (dis.disabled) {
    const where = {
      project: ".claude/settings.json",
      local: ".claude/settings.local.json",
      user: "~/.claude/settings.json",
      managed: "managed-settings.json",
    }[dis.scope] || dis.scope;
    problems.push(`"disableAllHooks": true (${where}) — ALLE Hooks sind abgeschaltet, guard läuft nicht.`);
  }

  for (const [event, spec] of Object.entries(CANONICAL_WIRING)) {
    const expectedPath = path.join(root, ".claude", "hooks", "guard", spec.file);
    const matches = entries.filter((e) => e.event === event);

    if (matches.length === 0) {
      problems.push(`${event}: kein guard-Hook in .claude/settings.json registriert`);
      perEvent[event] = { resolvedPath: null };
      continue;
    }
    const commandCount = matches.reduce((n, e) => n + e.commands.length, 0);
    if (matches.length > 1 || commandCount !== 1) {
      problems.push(`${event}: uneindeutige Verdrahtung — ${commandCount} guard-Kommandos registriert (erwartet: genau 1)`);
      perEvent[event] = { resolvedPath: null };
      continue;
    }

    const entry = matches[0];
    const command = entry.commands[0];
    const resolvedPath = resolveWiredScript(command, root);
    perEvent[event] = { resolvedPath };

    if (!resolvedPath) {
      problems.push(`${event}: Kommando "${command}" konnte nicht aufgelöst werden (erwartet $CLAUDE_PROJECT_DIR/.claude/hooks/guard/${spec.file})`);
      continue;
    }
    if (path.resolve(resolvedPath) !== path.resolve(expectedPath)) {
      problems.push(`${event} zeigt auf "${path.relative(root, resolvedPath)}" statt "${path.relative(root, expectedPath)}"`);
      continue;
    }
    if (!fs.existsSync(resolvedPath)) {
      problems.push(`${event}: registriertes Skript existiert nicht: ${path.relative(root, resolvedPath)}`);
      continue;
    }

    const expectedMatcher = spec.matcher;
    const actualMatcher = entry.matcher ?? null;
    const matcherOk = expectedMatcher === null ? actualMatcher === null : actualMatcher === expectedMatcher;
    if (!matcherOk) {
      problems.push(matcherProblem(event, actualMatcher, expectedMatcher));
    }
  }

  return { ok: problems.length === 0, problems, perEvent };
}

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
    // action:"warn" feuert immer "warned"; action:"block" feuert in enforce
    // "blocked", in monitor "would-block" (prompt.js ist mode-aware, spiegelt
    // pretool.js). Beide Modi als Treffer akzeptieren, je nach Modus.
    const wanted = mode === "monitor" ? ["would-block", "warned"] : ["blocked", "warned"];
    const r = spawnHook(dir, hooks.prompt, { prompt: sample });
    return ruleIdFired(r.events, id, wanted);
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

// M4: EINE Quelle der Wahrheit für den Regel-Dateiinhalt in diesem Modul —
// vorher lasen computeFingerprint() (intern) UND loadRules() UND diese
// Funktion je unabhängig von der Platte: drei Lesevorgänge, drei mögliche
// Zeitpunkte. Ein Edit genau zwischen zwei davon würde einen Fingerabdruck
// von Zustand A mit einer Probe von Zustand B versiegeln (nie eine falsche
// ✓-Behauptung, aber ein irreführender spurious-drift). Jetzt: ein Lesevorgang
// hier, dessen Ergebnis sowohl an computeFingerprint() (via opts.rulesSrc)
// als auch an den lokalen JSON.parse() weitergereicht wird.
function readRulesSource(cwd) {
  for (const p of [path.join(cwd, "guard.rules.json"), path.join(cwd, ".claude", "guard.rules.json")]) {
    if (fs.existsSync(p)) return { path: p, src: fs.readFileSync(p, "utf8") };
  }
  return { path: null, src: null };
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
  const conventionalHook = hookPath || path.join(root, ".claude", "hooks", "guard", "pretool.js");
  const conventionalDir = path.dirname(conventionalHook);
  const details = [];
  const checks = { registered: false, wired: false, rulesLoaded: false, uniqueIds: true, blocksSecret: false, allowsTemplate: false, auditWritable: false, auditDisabled: false };
  const emptyCoverage = { probed: 0, total: 0, unprobed: [] };

  // M4: EIN Lesevorgang der Regel-Datei für diesen ganzen Lauf — Ergebnis
  // geht sowohl in computeFingerprint() (opts.rulesSrc) als auch in den
  // lokalen JSON.parse() unten. Siehe readRulesSource()-Kommentar.
  const { path: rulesPath, src } = readRulesSource(root);

  // 1) Verdrahtung (grob) — computeFingerprint() liest/parst settings.json
  // bereits und scheitert identisch bei fehlender/kaputter Datei
  // (fp.registered=false, fp.events=[]); ein zweites Lesen wäre totes Code und
  // eine TOCTOU-Quelle. Dieser Check beweist nur "die vier Events sind
  // IRGENDWIE registriert und ein pretool.js liegt konventionell da" — er
  // sagt NICHTS darüber, ob das registrierte Kommando auf DIESES Skript zeigt
  // oder ob der Matcher die richtigen Tools erfasst. Das prüft Schritt 1b.
  const fp = computeFingerprint(root, src !== null ? { rulesSrc: src } : undefined);
  const registered = new Set(fp.events);
  const missing = HOOK_EVENTS.filter((e) => !registered.has(e));
  checks.registered = fp.registered && missing.length === 0 && fs.existsSync(conventionalHook);
  details.push({
    key: "registered", ok: checks.registered, label: "Hooks registriert",
    info: checks.registered ? fp.events.join(", ") : (fp.registered ? `fehlt: ${missing.join(", ")}` : "keine guard-Hooks in .claude/settings.json"),
  });

  // 1b) Verdrahtung (strukturell) — A10: das eigentliche Loch. Ein Kommando,
  // das innerhalb von .claude/hooks/guard/ auf ein ANDERES Skript zeigt
  // (Sabotage: pretool-neutered.js; Tippfehler; Merge-Artefakt), bleibt für
  // Schritt 1 oben "registered" (die Substring-Prüfung "hooks/guard/" greift),
  // aber Claude Code ruft nie pretool.js auf — der wahre Hook läuft ungeprüft.
  // Ebenso ein zu eng gefasster Matcher (PreToolUse: "Read" statt "*"): Claude
  // Code ruft den Hook für Bash nie auf, obwohl der Hook selbst tadellos ist.
  // Beide Fälle: verify() probte bisher IMMER den konventionellen Pfad direkt
  // (nie über den Matcher), also blieb es grün. Ab hier wird das tatsächlich
  // registrierte Skript aufgelöst und weiter unten AUCH tatsächlich beprobt.
  const wiring = checkWiring(root);
  checks.wired = wiring.ok;
  details.push({
    key: "wiring", ok: wiring.ok, label: "Verdrahtung geprüft",
    info: wiring.ok
      ? `${HOOK_EVENTS.length} Hooks zeigen auf die erwarteten Skripte, Matcher korrekt`
      : wiring.problems.join("; "),
  });

  // Beprobt wird ab jetzt das tatsächlich VERDRAHTETE Skript pro Event — nicht
  // mehr der konventionelle Pfad. Nur wenn ein Event gar nicht auflösbar ist
  // (z.B. nicht registriert — bereits oben als eigener Fehlschlag gemeldet),
  // fällt die Probe auf den konventionellen Pfad zurück, damit
  // Regel-Coverage weiterhin diagnostizierbar bleibt statt sofort leer zu sein.
  const hooks = {
    pretool: wiring.perEvent.PreToolUse.resolvedPath || conventionalHook,
    posttool: wiring.perEvent.PostToolUse.resolvedPath || path.join(conventionalDir, "posttool.js"),
    prompt: wiring.perEvent.UserPromptSubmit.resolvedPath || path.join(conventionalDir, "prompt.js"),
  };

  // 2) Regelwerk
  let rules = null;
  if (src !== null) {
    try {
      rules = JSON.parse(src);
    } catch (e) {
      process.stderr.write(`[guard] Regel-Datei fehlerhaft: ${rulesPath} — ${e.message}\n`);
    }
  }
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

  // C1: doppelte Regel-IDs. probeRule()/ruleIdFired() ordnen ein Feuern NUR
  // über die Regel-ID zu — bei zwei Regeln mit derselben ID matcht
  // pathBlocked()/commandBlocked() ohnehin immer nur die ERSTE (die zweite ist
  // bereits tote Konfiguration), aber die Probe des zweiten Regel-OBJEKTS wird
  // trotzdem als "probiert" gezählt, weil ihr Sample dieselbe ID im Audit-Log
  // auslöst. Ohne diesen Schutz: eine kopierte, umbenannte-vergessene Regel
  // gilt fälschlich als scharf, obwohl sie nie probiert wurde. Harter
  // Fehlschlag — eine doppelte ID ist ein eigenständiger Config-Bug.
  // Minor: eine Regel OHNE (oder mit leerer) ID ist ein eigenständiger
  // Config-Fehler, kein "ungeprüft"-Grenzfall. Ohne diese Wache landete
  // rule.id === undefined im selben seen-Set wie echte IDs (nie als Duplikat
  // erkannt, außer eine zweite Regel hatte ZUFÄLLIG ebenfalls keine ID) und
  // unten im Probe-Lauf als `unprobed: [undefined]` — eine irreführende,
  // nicht handlungsfähige Meldung statt einer ehrlichen Fehlerursache.
  const missingIdClasses = [];
  if (checks.rulesLoaded) {
    const seen = new Map();
    for (const cls of RULE_CLASSES) {
      for (const rule of rules[cls.key] || []) {
        const id = typeof rule.id === "string" ? rule.id.trim() : "";
        if (!id) { missingIdClasses.push(cls.key); continue; }
        seen.set(id, (seen.get(id) || 0) + 1);
      }
    }
    const dupes = [...seen.entries()].filter(([, n]) => n > 1).map(([id]) => id);
    checks.uniqueIds = dupes.length === 0 && missingIdClasses.length === 0;
    if (dupes.length) {
      details.push({
        key: "uniqueIds", ok: false, label: "Regel-IDs eindeutig",
        info: `doppelte Regel-ID: ${dupes.join(", ")} — jede Regel braucht eine eigene ID, sonst ist „probiert" nicht zuordenbar`,
      });
    }
    if (missingIdClasses.length) {
      details.push({
        key: "missingId", ok: false, label: "Regel-ID fehlt",
        info: `${missingIdClasses.length} Regel${missingIdClasses.length === 1 ? "" : "n"} ohne (oder leere) ID in: ${missingIdClasses.join(", ")} — jede Regel braucht eine eigene, nicht-leere ID, sonst ist „probiert" nicht zuordenbar`,
      });
    }
  }

  if (!checks.rulesLoaded || !fs.existsSync(hooks.pretool)) {
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

    for (const cls of RULE_CLASSES) {
      const arr = rules[cls.key] || [];
      let classProbed = 0;
      const classFailures = [];
      for (const rule of arr) {
        const id = typeof rule.id === "string" ? rule.id.trim() : "";
        // Bereits oben als Config-Fehler gemeldet (missingId) — hier NICHT
        // zusätzlich als "unprobed: [undefined]" verstecken.
        if (!id) continue;
        const sample = rule.sample !== undefined ? rule.sample : SHIPPED_SAMPLES[id];
        if (sample === undefined) { unprobed.push(id); continue; }
        const fired = probeRule(dir, hooks, cls.kind, id, sample, mode);
        if (fired) classProbed++; else classFailures.push(id);
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

    // 4) Blockt Secrets — die ECHTE Positivkontrolle. C-KRITISCH: das war
    // vorher `probedIds.has("path.dotenv")` — das fragt nur "hat IRGENDEINE
    // Regel mit der ID path.dotenv auf IHREM (nutzer-überschreibbaren) Muster
    // gefeuert?", nie "wird .env tatsächlich blockiert?". Wird das dotenv-Glob
    // verengt (z.B. **/.env → **/.env.production) und dazu ein passendes
    // eigenes "sample" gesetzt — genau das, wozu guards eigene Fehlermeldung
    // rät —, war dieser Check vorher grün, während `Read .env` im selben
    // Projekt tatsächlich ungehindert durchlief. Symmetrisch zu
    // allowsTemplate unten: ein echter, ID- und Sample-unabhängiger Spawn des
    // ECHTEN installierten Hooks gegen die ECHTEN, aktuell konfigurierten
    // Regeln — im selben audit-neutralisierten Wegwerf-cwd, damit das echte
    // Compliance-Log unangetastet bleibt.
    const wantedSecret = mode === "monitor" ? "would-block" : "blocked";
    const secretProbe = spawnHook(dir, hooks.pretool, { tool_name: "Read", tool_input: { file_path: ".env" } });
    checks.blocksSecret = secretProbe.events.some((e) => e.event === wantedSecret)
      && (mode === "monitor" || secretProbe.exitCode === 2);
    // I2: MUSS eine sichtbare Detail-Zeile bekommen, in BEIDEN Zuständen —
    // und die Zeile darf nur behaupten, was der Spawn oben tatsächlich zeigte.
    details.push({
      key: "blocksSecret", ok: checks.blocksSecret, label: "Blockt Secrets",
      info: checks.blocksSecret
        ? (mode === "monitor" ? ".env → würde blockiert (monitor)" : ".env → blockiert")
        : ".env wird NICHT blockiert — guard verify verlangt das als Positivkontrolle",
    });

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

    const ok = checks.registered && checks.wired && checks.rulesLoaded && checks.uniqueIds && checks.blocksSecret && checks.allowsTemplate && checks.auditWritable && !anyFailure;
    const coverage = { probed: probedTotal, total: ruleTotal, unprobed };
    return { ok, mode, ruleCount, fingerprint: fp.fingerprint, checks, details, coverage, auditDisabled };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

module.exports = { runVerify };
