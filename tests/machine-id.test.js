"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { machineId } = require("../hooks/lib.js");

// I3: Env-Divergenz. "guard verify" ausgeführt in einer Shell mit gesetztem
// XDG_CONFIG_HOME sieht eine ANDERE machine-id-Datei als der von Claude Code
// gespawnte Hook (der dieses env typischerweise nicht hat, oder umgekehrt) —
// ohne Fix legt jede Umgebung ihre EIGENE ID an, das Siegel passt nie
// zusammen, das Banner bleibt für immer bei "nicht verifiziert". Der Fix:
// wenn XDG_CONFIG_HOME gesetzt ist, aber dort noch keine ID liegt, zuerst am
// HOME-Fallback-Pfad nachsehen, BEVOR eine neue ID angelegt wird.
test("machineId(): XDG_CONFIG_HOME gesetzt aber ohne eigene ID → vorhandene HOME-ID wird wiederverwendet, keine zweite ID angelegt", () => {
  const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), "guard-mid-home-"));
  const homeIdDir = path.join(fakeHome, ".config", "elevenworks-guard");
  fs.mkdirSync(homeIdDir, { recursive: true });
  const homeId = "deadbeefdeadbeefdeadbeefdeadbeef";
  fs.writeFileSync(path.join(homeIdDir, "machine-id"), homeId + "\n");

  const xdgDir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-mid-xdg-"));

  const prevHome = process.env.HOME;
  const prevXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = fakeHome;
  process.env.XDG_CONFIG_HOME = xdgDir;
  try {
    const id = machineId();
    assert.strictEqual(id, homeId, "muss die vorhandene HOME-ID wiederverwenden, nicht neu anlegen");
    assert.ok(
      !fs.existsSync(path.join(xdgDir, "elevenworks-guard", "machine-id")),
      "darf KEINE zweite ID im XDG-Verzeichnis anlegen, solange die HOME-ID bereits existiert"
    );

    // Zweiter Aufruf: weiterhin konsistent dieselbe (HOME-)ID, kein Drift
    // zwischen zwei Aufrufen im selben Prozess.
    assert.strictEqual(machineId(), homeId);
  } finally {
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    if (prevXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prevXdg;
    fs.rmSync(fakeHome, { recursive: true, force: true });
    fs.rmSync(xdgDir, { recursive: true, force: true });
  }
});

// Gegenprobe: existiert weder unter XDG_CONFIG_HOME noch am HOME-Fallback eine
// ID, muss weiterhin eine NEUE ID unter XDG_CONFIG_HOME angelegt werden
// (unverändertes Verhalten für den Normalfall — reines Neuland).
test("machineId(): XDG_CONFIG_HOME gesetzt, weder dort noch am HOME-Fallback eine ID → legt neue ID unter XDG an", () => {
  const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), "guard-mid-home2-"));
  const xdgDir = fs.mkdtempSync(path.join(os.tmpdir(), "guard-mid-xdg2-"));

  const prevHome = process.env.HOME;
  const prevXdg = process.env.XDG_CONFIG_HOME;
  process.env.HOME = fakeHome;
  process.env.XDG_CONFIG_HOME = xdgDir;
  try {
    const id = machineId();
    assert.strictEqual(typeof id, "string");
    assert.ok(id.length > 0);
    assert.ok(fs.existsSync(path.join(xdgDir, "elevenworks-guard", "machine-id")), "muss eine ID unter dem XDG-Pfad anlegen, wenn nirgendwo eine existiert");
    assert.strictEqual(machineId(), id, "wiederholter Aufruf liefert dieselbe, jetzt persistierte ID");
  } finally {
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    if (prevXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prevXdg;
    fs.rmSync(fakeHome, { recursive: true, force: true });
    fs.rmSync(xdgDir, { recursive: true, force: true });
  }
});
