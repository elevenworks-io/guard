#!/usr/bin/env node
// @elevenworks/guard — UserPromptSubmit Hook
// Erkennt PII und Secrets im Prompt, bevor sie das Gerät verlassen.
// action "block" → Prompt wird gestoppt (enforce) bzw. nur protokolliert (monitor).
// action "warn"  → Hinweis an Claude, weiterarbeiten (mode-unabhängig).
"use strict";
const { readStdin, loadRules, scanPII, audit } = require("./lib.js");

const input = readStdin();
if (!input) process.exit(0);

const cwd = input.cwd || process.cwd();
const rules = loadRules(cwd);
if (!rules) process.exit(0);

const prompt = input.prompt || "";
const hits = scanPII(prompt, rules);

if (hits.length === 0) process.exit(0);

const blockers = hits.filter((h) => h.action === "block");
const warns = hits.filter((h) => h.action === "warn");

if (blockers.length > 0) {
  const list = [...new Set(blockers.map((b) => `${b.name} (${b.sample})`))].join(", ");
  // monitor: NICHT blockieren, nur als would-block protokollieren — deckungsgleich
  // mit pretool.js decide(). Sonst widerspräche der Modus seinem eigenen
  // Versprechen ("audit-only, nichts wird blockiert"): ein action:"block"-PII-
  // Treffer (IBAN, AWS-/Anthropic-Key, …) würde ein evaluierendes Team im
  // Monitor-Modus hart mit Exit 2 stoppen. Der Hinweis geht als JSON-
  // systemMessage NUR an den Nutzer (bei UserPromptSubmit landet plain-text-
  // stdout sonst im Modell-Kontext — hier unerwünscht).
  if ((rules.mode || "enforce") === "monitor") {
    audit({ event: "would-block", type: "pii-prompt", findings: blockers }, rules, cwd);
    process.stdout.write(JSON.stringify({
      systemMessage: `[guard] ⚠️ monitor-Modus: würde Prompt blockieren (sensible Daten: ${list}) — durchgelassen, protokolliert.`,
    }));
    process.exit(0);
  }
  audit({ event: "blocked", type: "pii-prompt", findings: blockers }, rules, cwd);
  process.stderr.write(
    `[guard] Prompt blockiert — enthält sensible Daten: ${list}. ` +
    `Bitte entfernen oder durch Platzhalter ersetzen, dann erneut senden.`
  );
  process.exit(2);
}

if (warns.length > 0) {
  audit({ event: "warned", type: "pii-prompt", findings: warns }, rules, cwd);
  const list = [...new Set(warns.map((w) => w.name))].join(", ");
  // stdout bei exit 0 wird dem Kontext hinzugefügt — Claude sieht den Hinweis.
  process.stdout.write(
    `[guard] Hinweis: Der Prompt enthält potenziell personenbezogene Daten (${list}). ` +
    `Behandle sie vertraulich, übernimm sie nicht in Code, Logs, Commits oder Dateien.`
  );
}
process.exit(0);
