"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { collectRuleIds } = require("./runner.js");

const RULES = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "templates", "guard.rules.json"), "utf8"));
const SAMPLES = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "templates", "guard.samples.json"), "utf8"));
const RULE_IDS = collectRuleIds(RULES);

// Die Garantie hinter "guard verify beweist jede Regel": JEDE Regel-ID im
// ausgelieferten Regelwerk muss ein Beweismuster in guard.samples.json haben.
// Ohne diesen Meta-Test könnte eine neue Regel unbemerkt ohne Muster ausgeliefert
// werden — genau die Lücke, die A6 schließt.
test("samples: jede Regel-ID aus guard.rules.json hat einen Eintrag in guard.samples.json", () => {
  const missing = [...RULE_IDS].filter((id) => !(id in SAMPLES));
  assert.strictEqual(missing.length, 0, `Regeln ohne Beweismuster: ${missing.join(", ")}`);
});

test("samples: keine verwaisten Einträge (jeder Sample-Key referenziert eine echte Regel-ID)", () => {
  const orphans = Object.keys(SAMPLES).filter((k) => !k.startsWith("$") && !RULE_IDS.has(k));
  assert.strictEqual(orphans.length, 0, `Beweismuster ohne zugehörige Regel: ${orphans.join(", ")}`);
});

test("samples: jedes Muster ist ein nichtleerer String", () => {
  for (const [id, sample] of Object.entries(SAMPLES)) {
    if (id.startsWith("$")) continue;
    assert.strictEqual(typeof sample, "string", `Muster für ${id} ist kein String`);
    assert.ok(sample.length > 0, `Muster für ${id} ist leer`);
  }
});

// --- C1: eine doppelte Regel-ID im ausgelieferten Template lässt guard verify
// eine Probe fälschlich einem Regel-OBJEKT zuordnen, das nie feuert (siehe
// tests/verify.test.js "C1: doppelte Regel-ID"). Diese Garantie darf im
// Template selbst nie regressen — RULE_IDS ist ein Set (dedupliziert bereits),
// daher hier eine eigene, ordnungserhaltende Zählung über alle vier Klassen. ---
test("samples: ausgeliefertes Template hat keine doppelten Regel-IDs über alle Regelklassen hinweg", () => {
  const allIds = [];
  for (const key of ["blockedPaths", "blockedCommands", "piiPatterns", "injectionPatterns"]) {
    for (const r of RULES[key] || []) allIds.push(r.id);
  }
  const counts = new Map();
  for (const id of allIds) counts.set(id, (counts.get(id) || 0) + 1);
  const dupes = [...counts.entries()].filter(([, n]) => n > 1).map(([id]) => id);
  assert.deepStrictEqual(dupes, [], `doppelte Regel-IDs im Template: ${dupes.join(", ")}`);
});
