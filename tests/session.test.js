"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const nodeOs = require("node:os");
const { computeFingerprint, realRoot, machineId } = require("../hooks/lib.js");

const PKG = path.join(__dirname, "..");
const HOOKS = ["lib.js", "pretool.js", "posttool.js", "prompt.js", "session.js"];

// I1: machineId() persistiert AUSSERHALB des Repos, unter XDG_CONFIG_HOME
// (Fallback ~/.config). Für Tests isolieren wir das in ein Wegwerf-Verzeichnis
// — sonst würde jeder Testlauf die echte ~/.config/elevenworks-guard/machine-id
// des Entwicklers anfassen. spawnSync() unten erbt process.env standardmäßig,
// die Kind-Hooks sehen also denselben XDG_CONFIG_HOME.
const XDG_TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "guard-xdg-"));
process.env.XDG_CONFIG_HOME = XDG_TEST_DIR;

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

// Standardmäßig ein Siegel für DIESE Maschine + diesen Checkout (host/root
// passend) — das ist der "gültiges Siegel"-Fall. Tests, die einen fremden
// Rechner/Checkout simulieren wollen, überschreiben host/root explizit.
function seal(d, over = {}) {
  const fp = computeFingerprint(d);
  fs.writeFileSync(path.join(d, ".claude", "guard-verified.json"), JSON.stringify({
    ts: "2026-07-13T14:23:11.000Z", guardVersion: "0.5.0", mode: "enforce",
    fingerprint: fp.fingerprint, ok: true,
    host: nodeOs.hostname(), root: realRoot(d),
    // I1: das Siegel dieser Maschine — passend zu machineId() im selben
    // (isolierten) XDG_CONFIG_HOME, den auch die gespawnten Hooks sehen.
    installId: machineId(),
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
  assert.strictEqual(ev.mode, null, "mode muss ehrlich null sein — die Compliance-Aufzeichnung darf keinen Modus erfinden");
  assert.strictEqual(ev.rules, 0, "rules muss 0 sein — kein Regelwerk gelesen, keine Regeln aktiv");
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

// --- C1: ein gereistes Siegel (committet, geklont) darf NIE "verifiziert" behaupten ---

test("session: sonst gültiges Siegel mit FREMDEM host/root → NICHT 'zuletzt verifiziert', sondern 'nicht verifiziert' (nicht 'fehlgeschlagen')", () => {
  const d = install();
  seal(d, { host: "irgendein-anderer-rechner", root: "/irgendwo/anders" });
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.doesNotMatch(r.banner, /zuletzt verifiziert/i, "ein gereistes Siegel darf niemals als 'verifiziert' erscheinen");
  assert.doesNotMatch(r.banner, /fehlgeschlagen/i, "ein gereistes Siegel ist NICHT fehlgeschlagen — es ist einfach nicht dieser Rechner");
  assert.match(r.banner, /nicht verifiziert/i);
  cleanup(d);
});

test("session: Siegel für DIESE Maschine + diesen Checkout → verifiziert normal (keine Überstrenge)", () => {
  const d = install();
  seal(d); // Standard-seal() setzt bereits host=os.hostname(), root=realRoot(d)
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.match(r.banner, /zuletzt verifiziert/i);
  cleanup(d);
});

test("session: numerischer cwd im Hook-Payload → trotzdem exit 0 (kein Crash aus path.join)", () => {
  const d = install();
  seal(d);
  const res = spawnSync(process.execPath, [path.join(d, ".claude", "hooks", "guard", "session.js")], {
    input: JSON.stringify({ hook_event_name: "SessionStart", source: "startup", session_id: "test-1", cwd: 12345 }),
    cwd: d, encoding: "utf8",
  });
  assert.strictEqual(res.status, 0);
  cleanup(d);
});

test("session: guard.rules.json ist ein JSON-Skalar → gilt als NICHT lesbar (kein '0 Regeln aktiv'-Overclaim)", () => {
  const d = install();
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify("hallo"));
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.match(r.banner, /nicht lesbar|greift nicht/i);
  assert.doesNotMatch(r.banner, /aktiv · 0 Regeln/i);
  cleanup(d);
});

// --- Minor: guard.rules.json ist ein Array → gilt ebenfalls als NICHT lesbar
// (typeof [] === "object", das reine typeof-Gate ließ das früher durch) ---

test("session: guard.rules.json ist ein JSON-Array → gilt als NICHT lesbar (Array.isArray-Lücke)", () => {
  const d = install();
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify([1, 2, 3]));
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.match(r.banner, /nicht lesbar|greift nicht/i);
  assert.doesNotMatch(r.banner, /aktiv · 0 Regeln/i);
  cleanup(d);
});

// --- I1: host+root sind in Devcontainern/CI oft deterministisch identisch —
// installId (AUSSERHALB des Repos persistiert) muss zusätzlich passen ---

test("session: Siegel mit FREMDER installId (host+root+fingerprint sonst korrekt) → NICHT 'zuletzt verifiziert'", () => {
  const d = install();
  seal(d, { installId: "ffffffffffffffffffffffffffffffff" });
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.doesNotMatch(r.banner, /zuletzt verifiziert/i, "eine fremde installId darf niemals als 'verifiziert' erscheinen");
  assert.doesNotMatch(r.banner, /fehlgeschlagen/i, "eine fremde installId ist NICHT fehlgeschlagen — es ist einfach nicht diese Installation");
  assert.match(r.banner, /nicht verifiziert/i);
  cleanup(d);
});

test("session: Siegel OHNE installId (älteres Siegel, host+root+fingerprint sonst korrekt) → NICHT 'zuletzt verifiziert'", () => {
  const d = install();
  seal(d, { installId: undefined });
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.doesNotMatch(r.banner, /zuletzt verifiziert/i, "ein Siegel ohne installId darf niemals als 'verifiziert' erscheinen");
  assert.doesNotMatch(r.banner, /fehlgeschlagen/i);
  assert.match(r.banner, /nicht verifiziert/i);
  cleanup(d);
});

test("session: Siegel MIT korrekter installId dieser Maschine → verifiziert normal (keine Überstrenge)", () => {
  const d = install();
  seal(d); // seal() setzt installId bereits auf machineId()
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.match(r.banner, /zuletzt verifiziert/i);
  cleanup(d);
});

// --- I2: audit.enabled:false — das Banner muss ehrlich sagen, dass kein
// Compliance-Log geschrieben wird, wenn das Siegel das dokumentiert ---

test("session: Siegel mit auditDisabled:true → Banner hängt 'Audit-Log deaktiviert' an", () => {
  const d = install();
  seal(d, { auditDisabled: true });
  const r = runSession(d);
  assert.strictEqual(r.exitCode, 0);
  assert.match(r.banner, /zuletzt verifiziert/i);
  assert.match(r.banner, /Audit-Log deaktiviert/i);
  cleanup(d);
});

test("session: Siegel mit auditDisabled:false → kein Deaktiviert-Hinweis im Banner", () => {
  const d = install();
  seal(d, { auditDisabled: false });
  const r = runSession(d);
  assert.match(r.banner, /zuletzt verifiziert/i);
  assert.doesNotMatch(r.banner, /Audit-Log deaktiviert/i);
  cleanup(d);
});

test("session: älteres Siegel ohne auditDisabled-Feld → kein Hinweis erfunden", () => {
  const d = install();
  seal(d, { auditDisabled: undefined });
  const r = runSession(d);
  assert.match(r.banner, /zuletzt verifiziert/i);
  assert.doesNotMatch(r.banner, /Audit-Log deaktiviert/i);
  cleanup(d);
});

test("session: machineId() nicht verfügbar (Config-Verzeichnis unschreibbar, ist eine Datei) → trotzdem exit 0, nie fälschlich verifiziert", () => {
  const d = install();
  seal(d, { installId: "irgendeine-fremde-id" });
  const unwritableXdg = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "guard-xdg-file-")), "not-a-dir");
  fs.writeFileSync(unwritableXdg, "ich bin eine Datei, kein Verzeichnis");
  const res = spawnSync(process.execPath, [path.join(d, ".claude", "hooks", "guard", "session.js")], {
    input: JSON.stringify({ hook_event_name: "SessionStart", source: "startup", session_id: "test-1", cwd: d }),
    cwd: d, encoding: "utf8",
    env: { ...process.env, XDG_CONFIG_HOME: unwritableXdg },
  });
  assert.strictEqual(res.status, 0, "machineId()-Fehler darf den Hook nie über exit 0 hinaus crashen lassen (fail-open)");
  let out = {};
  try { out = JSON.parse(res.stdout); } catch {}
  assert.doesNotMatch(out.systemMessage || "", /zuletzt verifiziert/i, "ein kaputtes machineId() darf NIE ein Siegel validieren");
});
