"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const { buildReport } = require("../lib/report.js");

const rules = {
  blockedPaths: [{ id: "path.dotenv", glob: "**/.env" }],
  blockedCommands: [{ id: "cmd.rm-rf", pattern: "x" }],
  piiPatterns: [{ id: "pii.iban", name: "IBAN", pattern: "y" }],
};
const audit = [
  { ts: "2026-07-11T10:00:00.000Z", event: "blocked", type: "path", tool: "Read", target: ".env", ruleId: "path.dotenv" },
  { ts: "2026-07-11T10:01:00.000Z", event: "blocked", type: "command", tool: "Bash", command: "rm -rf x", ruleId: "cmd.rm-rf" },
  { ts: "2026-07-11T10:02:00.000Z", event: "allowed", tool: "Read", target: "src/app.js" },
];

test("report has title, counts, grouped blocks, active rules", () => {
  const md = buildReport({ auditLines: audit, rules, now: "2026-07-11T10:05:00.000Z" });
  assert.match(md, /# guard — Nachweis/);
  assert.match(md, /2 blockiert/);                 // 2 blocked events
  assert.match(md, /path\.dotenv/);                // grouped by ruleId
  assert.match(md, /cmd\.rm-rf/);
  assert.match(md, /44|Regeln aktiv|3 Regeln/);    // active rule count reflected
  assert.match(md, /10:00/);                        // session start
});
test("empty audit yields honest empty report", () => {
  const md = buildReport({ auditLines: [], rules, now: "2026-07-11T10:05:00.000Z" });
  assert.match(md, /0 blockiert/);
});
