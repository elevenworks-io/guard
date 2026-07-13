"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const { runFixture } = require("./runner.js");

const readEnv = { hook: "pretool", input: { tool_name: "Read", tool_input: { file_path: ".env" } } };
const catEnv = { hook: "pretool", input: { tool_name: "Bash", tool_input: { command: "cat .env" } } };
const readExample = { hook: "pretool", input: { tool_name: "Read", tool_input: { file_path: ".env.example" } } };

test("monitor: geschützter Pfad wird durchgelassen (exit 0) + would-block geloggt", () => {
  const r = runFixture(readEnv, { mode: "monitor" });
  assert.strictEqual(r.exitCode, 0, "monitor darf nicht blocken");
  const ev = r.auditEvents.find((e) => e.event === "would-block");
  assert.ok(ev, "would-block-Event fehlt");
  assert.strictEqual(ev.ruleId, "path.dotenv");
  assert.strictEqual(ev.type, "path");
  assert.ok(!r.auditEvents.some((e) => e.event === "allowed"), "kein allowed bei Treffer");
  assert.match(r.stdout, /monitor/i, "systemMessage-Hinweis fehlt");
});

test("monitor: Bash-Kommando gegen Secret wird would-block geloggt, exit 0", () => {
  const r = runFixture(catEnv, { mode: "monitor" });
  assert.strictEqual(r.exitCode, 0);
  const ev = r.auditEvents.find((e) => e.event === "would-block");
  assert.ok(ev && ev.ruleId === "cmd.cat-secret", "cmd.cat-secret would-block fehlt");
});

test("monitor: erlaubter Pfad bleibt erlaubt (allowed, kein would-block)", () => {
  const r = runFixture(readExample, { mode: "monitor" });
  assert.strictEqual(r.exitCode, 0);
  assert.ok(r.auditEvents.some((e) => e.event === "allowed"));
  assert.ok(!r.auditEvents.some((e) => e.event === "would-block"));
});

test("enforce (Default): geschützter Pfad blockt weiterhin (exit 2 + blocked)", () => {
  const r = runFixture(readEnv);
  assert.strictEqual(r.exitCode, 2);
  assert.ok(r.auditEvents.some((e) => e.event === "blocked" && e.ruleId === "path.dotenv"));
});

// Fund #2: prompt.js war nicht mode-aware — ein action:"block"-PII-Treffer
// (IBAN, AWS-/Anthropic-Key) blockte hart mit Exit 2, auch im monitor-Modus,
// entgegen dessen Versprechen "nichts wird blockiert". Jetzt spiegelt prompt.js
// pretool.js: monitor → would-block + exit 0.
const ibanPrompt = { hook: "prompt", input: { prompt: "Überweisung an DE44500105175407324931 bitte" } };
const emailPrompt = { hook: "prompt", input: { prompt: "Schreib eine Mail an max@kunde.de" } };

test("monitor: block-PII im Prompt (IBAN) wird NICHT geblockt (exit 0) + would-block geloggt", () => {
  const r = runFixture(ibanPrompt, { mode: "monitor" });
  assert.strictEqual(r.exitCode, 0, "monitor darf den Prompt nicht blocken");
  const ev = r.auditEvents.find((e) => e.event === "would-block" && e.type === "pii-prompt");
  assert.ok(ev, "would-block-Event für pii-prompt fehlt");
  assert.ok(ev.findings.some((f) => f.ruleId === "pii.iban"), "pii.iban nicht in findings");
  assert.ok(!r.auditEvents.some((e) => e.event === "blocked"), "kein blocked im monitor");
  assert.match(r.stdout, /monitor/i, "systemMessage-Hinweis fehlt");
});

test("enforce (Default): block-PII im Prompt (IBAN) blockt weiterhin (exit 2 + blocked)", () => {
  const r = runFixture(ibanPrompt);
  assert.strictEqual(r.exitCode, 2);
  assert.ok(r.auditEvents.some((e) => e.event === "blocked" && e.type === "pii-prompt"
    && e.findings.some((f) => f.ruleId === "pii.iban")));
});

test("monitor: warn-PII im Prompt (E-Mail) bleibt Hinweis (exit 0, warned) — modus-unabhängig", () => {
  const r = runFixture(emailPrompt, { mode: "monitor" });
  assert.strictEqual(r.exitCode, 0);
  assert.ok(r.auditEvents.some((e) => e.event === "warned" && e.type === "pii-prompt"));
  assert.ok(!r.auditEvents.some((e) => e.event === "would-block"), "warn wird nicht zu would-block");
});
