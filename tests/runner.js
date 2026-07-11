"use strict";
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const HOOKS_DIR = path.join(__dirname, "..", "hooks");
const RULES_SRC = path.join(__dirname, "..", "templates", "guard.rules.json");

function runFixture(fixture) {
  const hookFile = fixture.hook === "prompt" ? "prompt.js" : "pretool.js";
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-fix-"));
  try {
    fs.copyFileSync(RULES_SRC, path.join(dir, "guard.rules.json"));
    const res = spawnSync(process.execPath, [path.join(HOOKS_DIR, hookFile)], {
      input: JSON.stringify(fixture.input),
      cwd: dir,
      encoding: "utf8",
    });
    const auditPath = path.join(dir, ".claude", "guard-audit.jsonl");
    let auditEvents = [];
    if (fs.existsSync(auditPath)) {
      auditEvents = fs.readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    }
    return { exitCode: res.status, stdout: res.stdout || "", stderr: res.stderr || "", auditEvents };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function collectRuleIds(rules) {
  const ids = new Set();
  for (const r of rules.blockedPaths || []) ids.add(r.id);
  for (const r of rules.blockedCommands || []) ids.add(r.id);
  for (const r of rules.piiPatterns || []) ids.add(r.id);
  return ids;
}

module.exports = { runFixture, collectRuleIds };
