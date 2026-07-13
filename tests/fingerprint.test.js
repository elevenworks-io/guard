"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { computeFingerprint, guardHookEntries, HOOK_FILES } = require("../hooks/lib.js");

const HOOKS = ["lib.js", "pretool.js", "posttool.js", "prompt.js", "session.js"];

// Baut eine realistische Installation im Temp-Verzeichnis.
function install() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "guard-fp-"));
  fs.mkdirSync(path.join(d, ".claude", "hooks", "guard"), { recursive: true });
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify({ mode: "enforce", blockedPaths: [{ id: "path.dotenv", glob: "**/.env" }] }));
  for (const f of HOOKS) fs.writeFileSync(path.join(d, ".claude", "hooks", "guard", f), `// ${f}\n`);
  fs.writeFileSync(path.join(d, ".claude", "settings.json"), JSON.stringify({
    hooks: {
      PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/pretool.js"' }] }],
      PostToolUse: [{ matcher: "Read|Bash", hooks: [{ type: "command", command: 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/posttool.js"' }] }],
      SessionStart: [{ matcher: "startup|resume", hooks: [{ type: "command", command: 'node "$CLAUDE_PROJECT_DIR/.claude/hooks/guard/session.js"' }] }],
    },
  }, null, 2));
  return d;
}
const cleanup = (d) => fs.rmSync(d, { recursive: true, force: true });

test("fingerprint: Basislauf ist registriert und stabil", () => {
  const d = install();
  const a = computeFingerprint(d);
  const b = computeFingerprint(d);
  assert.strictEqual(a.registered, true);
  assert.match(a.fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.strictEqual(a.fingerprint, b.fingerprint, "muss deterministisch sein");
  cleanup(d);
});

test("fingerprint: PreToolUse-Registrierung entfernt → ändert sich (DER kritische Fall)", () => {
  const d = install();
  const before = computeFingerprint(d).fingerprint;
  const p = path.join(d, ".claude", "settings.json");
  const s = JSON.parse(fs.readFileSync(p, "utf8"));
  delete s.hooks.PreToolUse;
  fs.writeFileSync(p, JSON.stringify(s));
  const after = computeFingerprint(d);
  assert.notStrictEqual(after.fingerprint, before, "ausgehängter Block-Hook MUSS das Siegel invalidieren");
  cleanup(d);
});

test("fingerprint: manipuliertes Hook-Skript → ändert sich", () => {
  const d = install();
  const before = computeFingerprint(d).fingerprint;
  fs.writeFileSync(path.join(d, ".claude", "hooks", "guard", "pretool.js"), "// entschärft\n");
  assert.notStrictEqual(computeFingerprint(d).fingerprint, before);
  cleanup(d);
});

test("fingerprint: geänderte Regeln → ändert sich", () => {
  const d = install();
  const before = computeFingerprint(d).fingerprint;
  fs.writeFileSync(path.join(d, "guard.rules.json"), JSON.stringify({ mode: "monitor", blockedPaths: [] }));
  assert.notStrictEqual(computeFingerprint(d).fingerprint, before);
  cleanup(d);
});

test("fingerprint: fremde Settings-Änderung → bleibt GLEICH", () => {
  const d = install();
  const before = computeFingerprint(d).fingerprint;
  const p = path.join(d, ".claude", "settings.json");
  const s = JSON.parse(fs.readFileSync(p, "utf8"));
  s.env = { SOMETHING: "1" };
  s.hooks.Stop = [{ hooks: [{ type: "command", command: "echo fremd" }] }];
  fs.writeFileSync(p, JSON.stringify(s, null, 2));
  assert.strictEqual(computeFingerprint(d).fingerprint, before, "fremde Settings dürfen das Siegel nicht invalidieren");
  cleanup(d);
});

test("fingerprint: keine guard-Registrierung → registered:false, kein stiller Erfolg", () => {
  const d = install();
  fs.writeFileSync(path.join(d, ".claude", "settings.json"), JSON.stringify({ hooks: {} }));
  const r = computeFingerprint(d);
  assert.strictEqual(r.registered, false);
  assert.strictEqual(r.fingerprint, null);
  cleanup(d);
});

test("fingerprint: fehlendes Hook-Skript ändert den Abdruck", () => {
  const d = install();
  const before = computeFingerprint(d).fingerprint;
  fs.rmSync(path.join(d, ".claude", "hooks", "guard", "posttool.js"));
  assert.notStrictEqual(computeFingerprint(d).fingerprint, before);
  cleanup(d);
});

// I2: HOOK_FILES ist die einzige Quelle der Wahrheit für "welche Hook-Skripte
// gibt es" — sowohl für den Fingerabdruck (hier) als auch für init()s Kopierliste
// (bin/cli.js). Wenn ein Skript hier fehlt, wird es nie gehasht und kann
// unbemerkt manipuliert werden, während das Siegel weiter "verifiziert" sagt.
test("HOOK_FILES: jede gelistete Datei existiert tatsächlich in hooks/", () => {
  const hooksDir = path.join(__dirname, "..", "hooks");
  for (const f of HOOK_FILES) {
    assert.ok(fs.existsSync(path.join(hooksDir, f)), `hooks/${f} fehlt, ist aber in HOOK_FILES gelistet`);
  }
  assert.deepStrictEqual([...HOOK_FILES].sort(), [...HOOKS].sort(), "HOOK_FILES muss exakt die bekannten Hook-Skripte abdecken");
});

test("guardHookEntries: extrahiert nur guard-Einträge, deterministisch sortiert", () => {
  const entries = guardHookEntries({
    hooks: {
      Stop: [{ hooks: [{ type: "command", command: "echo fremd" }] }],
      PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "node .claude/hooks/guard/pretool.js" }] }],
    },
  });
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].event, "PreToolUse");
});
