"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { computeFingerprint } = require("../hooks/lib.js");

const PKG = path.join(__dirname, "..");
const HOOKS = ["lib.js", "pretool.js", "posttool.js", "prompt.js", "session.js"];

function install({ mode = "enforce" } = {}) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "guard-ss-"));
  const gd = path.join(d, ".claude", "hooks", "guard");
  fs.mkdirSync(gd, { recursive: true });
  for (const f of HOOKS) fs.copyFileSync(path.join(PKG, "hooks", f), path.join(gd, f));
  const rules = JSON.parse(fs.readFileSync(path.join(PKG, "templates", "guard.rules.json"), "utf8"));
  rules.mode = mode;
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify(rules, null, 2));
  fs.writeFileSync(path.join(d, ".claude", "settings.json"), JSON.stringify({
    hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "node .claude/hooks/guard/pretool.js" }] }] },
  }, null, 2));
  return d;
}
const cleanup = (d) => fs.rmSync(d, { recursive: true, force: true });

// Führt den INSTALLIERTEN session.js aus (so, wie Claude Code es täte).
function runSession(d, source = "startup") {
  const res = spawnSync(process.execPath, [path.join(d, ".claude", "hooks", "guard", "session.js")], {
    input: JSON.stringify({ hook_event_name: "SessionStart", source, session_id: "test-1", cwd: d }),
    cwd: d, encoding: "utf8",
  });
  let out = {};
  try { out = JSON.parse(res.stdout); } catch {}
  const auditFile = path.join(d, ".claude", "guard-audit.jsonl");
  const events = fs.existsSync(auditFile)
    ? fs.readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse) : [];
  return { exitCode: res.status, out, banner: out.systemMessage || "", events };
}

function seal(d, over = {}) {
  const fp = computeFingerprint(d);
  fs.writeFileSync(path.join(d, ".claude", "guard-verified.json"), JSON.stringify({
    ts: "2026-07-13T14:23:11.000Z", guardVersion: "0.5.0", mode: "enforce",
    fingerprint: fp.fingerprint, ok: true,
    checks: { registered: true, blocksSecret: true, allowsTemplate: true, auditWritable: true },
    ...over,
  }, null, 2));
}

test("session: kein Siegel → Banner warnt 'nicht verifiziert'", () => {
  const d = install();
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.match(r.banner, /nicht verifiziert/i);
  assert.match(r.banner, /guard/i);
  cleanup(d);
});

test("session: gültiges Siegel → Banner meldet 'zuletzt verifiziert'", () => {
  const d = install();
  seal(d);
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.match(r.banner, /zuletzt verifiziert/i);
  assert.doesNotMatch(r.banner, /nicht verifiziert/i);
  cleanup(d);
});

test("session: Fingerabdruck weicht ab → Banner warnt vor Drift", () => {
  const d = install();
  seal(d, { fingerprint: "sha256:deadbeef" });
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.match(r.banner, /geändert|erneut verifizieren/i);
  cleanup(d);
});

test("session: Siegel ok:false → Banner meldet FEHLGESCHLAGEN", () => {
  const d = install();
  seal(d, { ok: false });
  const r = runSession(d);
  assert.match(r.banner, /fehlgeschlagen/i);
  cleanup(d);
});

test("session: monitor-Modus → Banner warnt 'blockt nicht'", () => {
  const d = install({ mode: "monitor" });
  seal(d);   // Siegel passt zum monitor-Regelwerk (Fingerabdruck darüber berechnet)
  const r = runSession(d);
  assert.match(r.banner, /monitor/i);
  assert.match(r.banner, /blockt nicht/i);
  cleanup(d);
});

test("session: schreibt ein session-start-Audit-Event", () => {
  const d = install();
  seal(d);
  const r = runSession(d, "startup");
  const ev = r.events.find((e) => e.event === "session-start");
  assert.ok(ev, "session-start-Event fehlt");
  assert.strictEqual(ev.source, "startup");
  assert.strictEqual(ev.sessionId, "test-1");
  assert.strictEqual(ev.mode, "enforce");
  assert.strictEqual(ev.verified, true);
  assert.ok(typeof ev.rules === "number" && ev.rules > 0);
  cleanup(d);
});

test("session: liefert additionalContext für Claude", () => {
  const d = install();
  seal(d);
  const r = runSession(d);
  assert.strictEqual(r.out.hookSpecificOutput?.hookEventName, "SessionStart");
  assert.match(r.out.hookSpecificOutput?.additionalContext || "", /guard/i);
  cleanup(d);
});

test("session: fail-open — kaputter stdin blockt nie (exit 0)", () => {
  const d = install();
  const res = spawnSync(process.execPath, [path.join(d, ".claude", "hooks", "guard", "session.js")], {
    input: "kein json", cwd: d, encoding: "utf8",
  });
  assert.strictEqual(res.status, 0);
  cleanup(d);
});

test("session: fehlendes Regelwerk → Banner sagt ehrlich, dass guard nicht greift, exit 0", () => {
  const d = install();
  fs.rmSync(path.join(d, "guard.rules.json"));
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.match(r.banner, /nicht lesbar|greift nicht/i);
  cleanup(d);
});

test("session: Siegel ohne 'ok'-Feld → NIE 'zuletzt verifiziert' (false positive)", () => {
  const d = install();
  seal(d, { ok: undefined });
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.doesNotMatch(r.banner, /zuletzt verifiziert/i);
  assert.match(r.banner, /fehlgeschlagen/i);
  cleanup(d);
});

test("session: Siegel ok:true ohne 'fingerprint'-Feld → NIE 'zuletzt verifiziert'", () => {
  const d = install();
  seal(d, { fingerprint: undefined });
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.doesNotMatch(r.banner, /zuletzt verifiziert/i);
  assert.match(r.banner, /fehlgeschlagen/i);
  cleanup(d);
});

test("session: Siegel mit passendem Fingerabdruck aber kaputtem 'ts' → NIE verifiziert, NIE NaN", () => {
  const d = install();
  seal(d, { ts: "kaputt" });
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.doesNotMatch(r.banner, /zuletzt verifiziert/i);
  assert.doesNotMatch(r.banner, /NaN/i);
  assert.match(r.banner, /fehlgeschlagen/i);
  cleanup(d);
});

test("session: Regelwerk unlesbar → trotzdem session-start-Audit-Event (verified:false), exit 0", () => {
  const d = install();
  fs.rmSync(path.join(d, "guard.rules.json"));
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  const ev = r.events.find((e) => e.event === "session-start");
  assert.ok(ev, "session-start-Event fehlt im Regelwerk-unlesbar-Fall");
  assert.strictEqual(ev.verified, false);
  cleanup(d);
});

test("session: Fingerabdruck-Berechnung wirft (EISDIR) → trotzdem exit 0 und Banner", () => {
  const d = install();
  seal(d);
  const hookFile = path.join(d, ".claude", "hooks", "guard", "posttool.js");
  fs.rmSync(hookFile);
  fs.mkdirSync(hookFile);
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.ok(r.banner && r.banner.length > 0, "Banner fehlt trotz fail-open-Anspruch");
  cleanup(d);
});
