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
