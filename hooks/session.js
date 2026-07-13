#!/usr/bin/env node
// @elevenworks/guard — SessionStart-Hook.
// Meldet beim Start sichtbar, ob guard verdrahtet, scharf und verifiziert ist.
// Der Beweis wird von Claude Code selbst erzeugt: dieses Banner kann nur
// erscheinen, wenn Claude Code guard tatsächlich ausführt.
// Behauptet NIE mehr, als das Siegel belegt. Blockt nie (immer exit 0).
"use strict";
const { readStdin, loadRules, audit, computeFingerprint, readSeal } = require("./lib.js");

function countRules(rules) {
  return (rules.blockedPaths?.length || 0) + (rules.blockedCommands?.length || 0)
    + (rules.piiPatterns?.length || 0) + (rules.injectionPatterns?.length || 0);
}

function emit(systemMessage, additionalContext) {
  process.stdout.write(JSON.stringify({
    systemMessage,
    hookSpecificOutput: { hookEventName: "SessionStart", additionalContext },
  }));
  process.exit(0);
}

const input = readStdin() || {};
const cwd = input.cwd || process.cwd();
const rules = loadRules(cwd);

if (!rules) {
  // Auch der "guard greift nicht"-Fall MUSS ein Audit-Event erzeugen — das
  // ist genau der Zustand, in dem ein Compliance-Nachweis am wichtigsten ist.
  // audit() toleriert rules=null (nutzt dann den Default-Pfad).
  audit({
    event: "session-start",
    source: input.source || "startup",
    sessionId: input.session_id || null,
    mode: null,
    rules: 0,
    verified: false,
  }, null, cwd);
  emit(
    "[guard] ⚠ Regelwerk nicht lesbar — guard greift nicht. Prüfe guard.rules.json.",
    "[guard] Hinweis: guards Regelwerk ist nicht lesbar, es greift derzeit KEIN Schutz."
  );
}

const mode = rules.mode || "enforce";
const n = countRules(rules);
const seal = readSeal(cwd);

// Das Siegel wird NICHT vom Fingerabdruck erfasst (es ist dessen Ausgabe) —
// es ist also nicht vertrauenswürdige Eingabe und muss strikt validiert werden.
// computeFingerprint() liest Dateien ohne vollständigen Schutz vor EISDIR/
// Rechte-/TOCTOU-Fehlern; ein SessionStart-Hook darf dadurch NIE crashen
// (exit 0 ist ein hartes Muss). Also: alles in try/catch, im Fehlerfall
// ehrlich auf "failed" degradieren statt eine ungeprüfte Behauptung zu machen.
let state = "failed";
try {
  const fp = computeFingerprint(cwd);
  if (!seal) {
    state = "none";
  } else {
    const sealValid = seal.ok === true
      && typeof seal.fingerprint === "string"
      && !Number.isNaN(new Date(seal.ts).getTime());
    state = !sealValid ? "failed"
      : (!fp.fingerprint || seal.fingerprint !== fp.fingerprint) ? "drift"
      : "verified";
  }
} catch {
  state = "failed";
}

const verifiedAt = () => {
  const d = new Date(seal.ts);
  const p = (x) => String(x).padStart(2, "0");
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}. ${p(d.getHours())}:${p(d.getMinutes())}`;
};

const tail = {
  verified: () => `zuletzt verifiziert: ${verifiedAt()} ✓`,
  none: () => '⚠ nicht verifiziert — "npx @elevenworks/guard verify" ausführen',
  drift: () => "⚠ Verdrahtung/Regeln/Hooks seit der Verifikation geändert — erneut verifizieren",
  failed: () => '⚠ letzte Verifikation FEHLGESCHLAGEN — "guard verify" prüfen',
}[state]();

let banner = `[guard] aktiv · ${n} Regeln · ${mode} · ${tail}`;
if (mode === "monitor") banner += "  ⚠ monitor-Modus — beobachtet nur, blockt nicht";

audit({
  event: "session-start",
  source: input.source || "startup",
  sessionId: input.session_id || null,
  mode,
  rules: n,
  verified: state === "verified",
}, rules, cwd);

emit(
  banner,
  `[guard] aktiv: ${n} Regeln, Modus ${mode}, Verifikation: ${state}. `
  + "Zugriffe auf Secrets/geschützte Pfade werden geprüft; Blocks sind erwartbar und kein Fehler — "
  + "weiche dann auf eine freigegebene Alternative aus, statt den Schutz zu umgehen."
);
