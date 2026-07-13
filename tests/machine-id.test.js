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

// I-WICHTIG (4. Review): Gegenprobe — existiert weder unter XDG_CONFIG_HOME
// noch am HOME-Fallback eine ID, wird zwar weiterhin eine NEUE ID unter
// XDG_CONFIG_HOME angelegt, aber sie muss zusätzlich an den HOME-Fallback
// gespiegelt werden. Ohne den Spiegel: eine Shell MIT gesetztem
// XDG_CONFIG_HOME (z.B. "guard verify" manuell ausgeführt) mintet die ID nur
// unter XDG — Claude Code selbst (GUI-Start, kein Shell-Profil, ohne dieses
// env) sieht sie nie und mintet unabhängig eine ZWEITE ID unter ~/.config.
// Diese Variante war vorher fälschlich als "intended behaviour" codiert
// (nur der XDG-Pfad wurde geprüft) — genau das verdeckte die Zwei-ID-Lücke.
test("machineId(): frische Maschine, XDG_CONFIG_HOME gesetzt, nirgendwo eine ID → neue ID wird an BEIDEN Orten abgelegt, ein Leser OHNE XDG sieht dieselbe ID", () => {
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
    const xdgFile = path.join(xdgDir, "elevenworks-guard", "machine-id");
    const homeFile = path.join(fakeHome, ".config", "elevenworks-guard", "machine-id");
    assert.ok(fs.existsSync(xdgFile), "muss eine ID unter dem XDG-Pfad anlegen, wenn nirgendwo eine existiert");
    assert.ok(fs.existsSync(homeFile), "muss die frische ID zusätzlich an den HOME-Fallback spiegeln");
    assert.strictEqual(fs.readFileSync(homeFile, "utf8").trim(), id, "HOME-Spiegel muss dieselbe ID enthalten wie der XDG-Pfad");
    assert.strictEqual(machineId(), id, "wiederholter Aufruf (weiterhin mit XDG) liefert dieselbe, jetzt persistierte ID");

    // Der eigentliche Bug-Reproduktionsfall: ein Leser OHNE XDG_CONFIG_HOME
    // (z.B. Claude Code, per GUI ohne Shell-Profil gespawnt) muss dieselbe ID
    // sehen wie der Schreiber mit XDG — sonst zwei IDs, Siegel passt nie.
    delete process.env.XDG_CONFIG_HOME;
    assert.strictEqual(machineId(), id, "ein Leser ohne XDG_CONFIG_HOME muss dieselbe ID sehen wie der Schreiber mit XDG — sonst divergieren installId und machineId() für immer");
  } finally {
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    if (prevXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prevXdg;
    fs.rmSync(fakeHome, { recursive: true, force: true });
    fs.rmSync(xdgDir, { recursive: true, force: true });
  }
});
