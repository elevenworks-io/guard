#!/usr/bin/env node
// @elevenworks/guard — SessionStart-Hook.
// Meldet beim Start sichtbar, ob guard verdrahtet, scharf und verifiziert ist.
// Der Beweis wird von Claude Code selbst erzeugt: dieses Banner kann nur
// erscheinen, wenn Claude Code guard tatsächlich ausführt.
// Behauptet NIE mehr, als das Siegel belegt. Blockt nie (immer exit 0).
"use strict";

// Muss ganz oben stehen: jeder unerwartete Crash — auch aus dem unguarded
// process.stdout.write() in emit(), oder aus loadRules()/path.join(), wenn
// input.cwd kein String ist — darf NIE über exit 0 hinausblocken. guard soll
// nie zwischen Claude und die eigentliche Arbeit treten.
process.on("uncaughtException", () => process.exit(0));

const os = require("os");
const { readStdin, loadRules, audit, computeFingerprint, readSeal, realRoot, machineId } = require("./lib.js");

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
const cwd = typeof input.cwd === "string" ? input.cwd : process.cwd();
const rules = loadRules(cwd);

if (!rules || typeof rules !== "object" || Array.isArray(rules)) {
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
//
// I4: fp wird AUSSERHALB des try deklariert (Default: nichts registriert) und
// von computeFingerprint() innerhalb neu zugewiesen — das Banner unten braucht
// fp.events, um zu erkennen, ob der Block-Hook (PreToolUse) überhaupt noch in
// settings.json registriert ist. Das ist unabhängig vom Siegel-Vergleich: auch
// ohne Siegel, mit Drift oder fehlgeschlagener Verifikation muss "der
// Block-Hook läuft gerade gar nicht" die lauteste Meldung sein — genau der
// Zustand, den dieses Feature verhindern soll.
let fp = { fingerprint: null, registered: false, events: [] };
let state = "failed";
try {
  fp = computeFingerprint(cwd);
  if (!seal) {
    state = "none";
  } else {
    const sealValid = seal.ok === true
      && typeof seal.fingerprint === "string"
      && !Number.isNaN(new Date(seal.ts).getTime());
    if (!sealValid) {
      state = "failed";
    } else {
      // I1: host+root allein reichen in Devcontainern/CI nicht — dort sind
      // beide auf jeder Maschine deterministisch gleich (Hostname =
      // Servicename, Arbeitsverzeichnis = /workspaces/… oder /app). Ein
      // committetes/geklontes Siegel würde sonst dort trotzdem überall
      // "verifiziert" gelten. installId ist AUSSERHALB des Repos persistiert
      // und macht das Siegel wirklich maschinenlokal.
      //
      // Strikter, nicht-lax Vergleich mit Pflicht auf beiden Seiten: ein
      // kaputtes machineId() (Config-Verzeichnis nicht schreibbar → null)
      // darf NIE ein installId-loses Siegel validieren — sonst würde ein
      // Fehler auf dieser Maschine zu einem falschen "verifiziert" führen,
      // statt zur ehrlichen Degradation.
      const mid = machineId();
      const installIdOk = typeof seal.installId === "string" && seal.installId.length > 0
        && typeof mid === "string" && mid.length > 0
        && seal.installId === mid;

      // Ein Siegel ohne maschinenlokalen Bezug ist kein Beweis für DIESE
      // Maschine/diesen Checkout — z. B. wenn versehentlich committet und
      // geklont. Das ist keine fehlgeschlagene Verifikation, sondern schlicht
      // keine für diesen Rechner: ehrliche Degradation auf "none", nicht
      // "failed" (das würde eine tatsächlich gescheiterte Prüfung suggerieren).
      const travelled = seal.host !== os.hostname() || seal.root !== realRoot(cwd) || !installIdOk;
      state = travelled ? "none"
        : (!fp.fingerprint || seal.fingerprint !== fp.fingerprint) ? "drift"
        : "verified";
    }
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

// I4: die Verdrahtungs-Lücke, die guard verify NIE selbst erkennen kann — sie
// betrifft settings.json JETZT, im laufenden Prozess, nicht den Stand von der
// letzten Verifikation. Wird PreToolUse aus settings.json entfernt, blockt
// pretool.js gar nicht mehr, aber ohne diesen Check bliebe das Banner bei
// "aktiv · N Regeln · enforce · …" — genau die Überbehauptung, die dieses
// Feature verhindern soll ("Blocks sind erwartbar", obwohl keiner mehr kommt).
// registeredSet ist LEER, wenn GAR KEIN guard-Hook mehr registriert ist — dann
// wäre dieser Hook selbst gar nicht aufgerufen worden; die Prüfung greift also
// nur sinnvoll, wenn fp.registered true ist (mindestens SessionStart lief ja
// gerade, sonst gäbe es dieses Banner nicht).
const registeredSet = new Set(fp.events);
const preToolMissing = fp.registered && !registeredSet.has("PreToolUse");
const postToolMissing = fp.registered && !registeredSet.has("PostToolUse");
const promptMissing = fp.registered && !registeredSet.has("UserPromptSubmit");

let banner;
let additionalContext;

if (preToolMissing) {
  // Der laute Fall: OHNE PreToolUse wird NICHTS mehr blockiert — Secrets/
  // geschützte Pfade sind vollständig ungeschützt, unabhängig davon, was das
  // Siegel zuletzt bezeugt hat. Diese Tatsache überschreibt jede andere
  // Banner-Aussage (verified/drift/failed/none) — sie wäre sonst irreführend
  // beruhigend ("zuletzt verifiziert ✓" bei einem Hook, der gerade gar nicht
  // läuft).
  const alsoMissing = [];
  if (postToolMissing) alsoMissing.push("PostToolUse (Injection-Erkennung)");
  if (promptMissing) alsoMissing.push("UserPromptSubmit (PII-Erkennung)");
  banner = '[guard] ⚠ Block-Hook NICHT registriert — es wird derzeit NICHTS blockiert. "npx @elevenworks/guard init" ausführen.';
  if (alsoMissing.length) banner += ` Ebenfalls nicht registriert: ${alsoMissing.join(", ")}.`;
  additionalContext = "[guard] ⚠ Der PreToolUse-Block-Hook ist NICHT in .claude/settings.json registriert — "
    + "es wird aktuell NICHTS blockiert, Zugriffe auf Secrets/geschützte Pfade werden NICHT geprüft. "
    + 'Blocks sind in diesem Zustand NICHT zu erwarten. "npx @elevenworks/guard init" ausführen, um die Verdrahtung wiederherzustellen.';
} else {
  banner = `[guard] aktiv · ${n} Regeln · ${mode} · ${tail}`;

  // Deckungsgrad aus dem Siegel — NUR anhängen, wenn das Siegel tatsächlich eins
  // trägt (ältere Siegel ohne coverage-Feld: Suffix weglassen statt eins zu
  // erfinden) und nur im "verified"-Zustand (sonst gibt es keine gültige Probe,
  // über die man reden könnte).
  if (state === "verified" && seal && seal.coverage
      && typeof seal.coverage.probed === "number" && typeof seal.coverage.total === "number") {
    const { probed, total, unprobed } = seal.coverage;
    const u = Array.isArray(unprobed) ? unprobed.length : 0;
    banner += u > 0 ? ` · ${probed}/${total} probiert (${u} ungeprüft)` : ` · ${probed}/${total} Regeln probiert`;
  }

  if (mode === "monitor") banner += "  ⚠ monitor-Modus — beobachtet nur, blockt nicht";

  // I2: audit.enabled:false bedeutet, dass audit() ein No-Op ist — es entsteht
  // KEIN Compliance-Log. Nur anhängen, wenn das SIEGEL das Feld tatsächlich
  // trägt (neuere Siegel) und nur im "verified"-Zustand — sonst gäbe es keine
  // vertrauenswürdige Grundlage, über die man reden könnte. Ein älteres Siegel
  // ohne dieses Feld: Suffix weglassen statt ihn zu erfinden.
  if (state === "verified" && seal && seal.auditDisabled === true) {
    banner += "  ⚠ Audit-Log deaktiviert — kein Nachweis";
  }

  // I4 (schwächer): PostToolUse/UserPromptSubmit blocken nie, sie warnen/
  // scannen nur — ihr Fehlen ist kein "nichts wird geschützt", aber trotzdem
  // eine echte Lücke (Injection-Erkennung bzw. PII-Erkennung inaktiv), die das
  // Banner nicht verschweigen darf.
  const weaker = [];
  if (postToolMissing) weaker.push("PostToolUse/Injection-Erkennung nicht registriert");
  if (promptMissing) weaker.push("UserPromptSubmit/PII-Erkennung nicht registriert");
  if (weaker.length) banner += `  ⚠ ${weaker.join(", ")}`;

  additionalContext = `[guard] aktiv: ${n} Regeln, Modus ${mode}, Verifikation: ${state}. `
    + "Zugriffe auf Secrets/geschützte Pfade werden geprüft; Blocks sind erwartbar und kein Fehler — "
    + "weiche dann auf eine freigegebene Alternative aus, statt den Schutz zu umgehen.";
}

audit({
  event: "session-start",
  source: input.source || "startup",
  sessionId: input.session_id || null,
  mode,
  rules: n,
  verified: state === "verified",
}, rules, cwd);

emit(banner, additionalContext);
