"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const PKG = path.join(__dirname, "..");
const CLI = path.join(PKG, "bin", "cli.js");
const HOOK_FILES = ["lib.js", "pretool.js", "posttool.js", "prompt.js", "session.js"];

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "guard-cli-init-"));
}
const cleanup = (d) => fs.rmSync(d, { recursive: true, force: true });

function runInit(cwd) {
  return spawnSync(process.execPath, [CLI, "init"], { cwd, encoding: "utf8" });
}

function settingsOf(d) {
  return JSON.parse(fs.readFileSync(path.join(d, ".claude", "settings.json"), "utf8"));
}

test("cli init: registriert alle vier Events mit den korrekten Matchern", () => {
  const d = tmpdir();
  const res = runInit(d);
  assert.strictEqual(res.status, 0, res.stdout + res.stderr);

  const settings = settingsOf(d);
  const pre = settings.hooks.PreToolUse[0];
  assert.strictEqual(pre.matcher, "*");
  assert.match(pre.hooks[0].command, /hooks\/guard\/pretool\.js/);

  const post = settings.hooks.PostToolUse[0];
  assert.strictEqual(post.matcher, "Read|Bash");
  assert.match(post.hooks[0].command, /hooks\/guard\/posttool\.js/);

  const prompt = settings.hooks.UserPromptSubmit[0];
  assert.strictEqual(prompt.matcher, undefined, "UserPromptSubmit hat keinen Matcher");
  assert.match(prompt.hooks[0].command, /hooks\/guard\/prompt\.js/);

  const session = settings.hooks.SessionStart[0];
  assert.strictEqual(session.matcher, "startup|resume");
  assert.match(session.hooks[0].command, /hooks\/guard\/session\.js/);

  cleanup(d);
});

test("cli init: zweimaliges Ausführen ist idempotent (keine Duplikate pro Event)", () => {
  const d = tmpdir();
  runInit(d);
  const res2 = runInit(d);
  assert.strictEqual(res2.status, 0, res2.stdout + res2.stderr);

  const settings = settingsOf(d);
  for (const event of ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"]) {
    assert.strictEqual(settings.hooks[event].length, 1, `${event} hat Duplikate nach zweitem init`);
  }
  cleanup(d);
});

test("cli init: schreibt das Siegel und trägt beide Pfade in .gitignore ein", () => {
  const d = tmpdir();
  const res = runInit(d);
  assert.strictEqual(res.status, 0, res.stdout + res.stderr);

  const sealPath = path.join(d, ".claude", "guard-verified.json");
  assert.ok(fs.existsSync(sealPath), "Siegel wurde nicht geschrieben");
  const seal = JSON.parse(fs.readFileSync(sealPath, "utf8"));
  assert.strictEqual(seal.ok, true);
  assert.ok(typeof seal.host === "string" && seal.host.length > 0, "Siegel muss host tragen");
  assert.ok(typeof seal.root === "string" && seal.root.length > 0, "Siegel muss root tragen");

  const gitignore = fs.readFileSync(path.join(d, ".gitignore"), "utf8");
  assert.match(gitignore, /\.claude\/guard-audit\.jsonl/);
  assert.match(gitignore, /\.claude\/guard-verified\.json/);
  cleanup(d);
});

test("cli init: kaputte Installation (keine blockedPaths) → exit 1, aber KEIN Rollback", () => {
  const d = tmpdir();
  // guard.rules.json VORAB anlegen, damit init es nicht überschreibt (init
  // überschreibt ein vorhandenes Regelwerk nie) — mit entschärften Regeln,
  // sodass der automatische Selbsttest (blocksSecret) fehlschlägt.
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify({ mode: "enforce", blockedPaths: [] }));
  const res = runInit(d);
  assert.strictEqual(res.status, 1, "eine kaputte Installation muss guard init mit exit 1 melden");

  // Kein Rollback: die kopierten Hook-Dateien und die settings.json-Einträge
  // müssen trotz gescheitertem Selbsttest bestehen bleiben — eine
  // Teil-Installation ist besser als ein leerer Ordner, und der Nutzer
  // braucht die Diagnose, nicht einen zurückgerollten Zustand.
  for (const f of HOOK_FILES) {
    assert.ok(fs.existsSync(path.join(d, ".claude", "hooks", "guard", f)), `hooks/guard/${f} wurde trotz Fehlschlag entfernt`);
  }
  const settings = settingsOf(d);
  for (const event of ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"]) {
    assert.ok(settings.hooks[event] && settings.hooks[event].length > 0, `${event}-Registrierung wurde trotz Fehlschlag entfernt`);
  }
  cleanup(d);
});
