"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { pathBlocked, commandBlocked, scanPII } = require("../hooks/lib.js");
const rules = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "templates", "guard.rules.json"), "utf8"));

test("pathBlocked returns rule object with id", () => {
  const hit = pathBlocked("config/.env", rules);
  assert.ok(hit && hit.id === "path.dotenv");
});
test("commandBlocked returns rule with id", () => {
  const hit = commandBlocked("git push origin main --force", rules);
  assert.ok(hit && hit.id === "cmd.force-push");
});
test("scanPII attaches ruleId", () => {
  const hits = scanPII("IBAN DE44500105175407324931", rules);
  assert.ok(hits.some((h) => h.ruleId === "pii.iban"));
});
