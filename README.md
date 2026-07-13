# @elevenworks/guard

Der Sicherheitsgurt für Claude Code. Secret-Blocker, Command-Denylist, PII-Erkennung, Audit-Log — installiert in einer Minute.

```
npx @elevenworks/guard init
✓ 49 Regeln aktiv
```

## Was guard macht

| Schutz | Mechanik | Hook |
|---|---|---|
| Secrets unsichtbar | `.env`, Keys, Credentials — Lese-Zugriff wird blockiert | PreToolUse |
| Gefährliche Kommandos | `rm -rf`, Force-Push, `curl \| sh`, `DROP TABLE`, … | PreToolUse |
| PII-Erkennung | E-Mail, IBAN, Steuer-ID, API-Keys im Prompt | UserPromptSubmit |
| Injection-Erkennung | Muster im gelesenen Inhalt | PostToolUse |
| Audit-Log | Jede Entscheidung als JSONL, revisionsfähig | alle |

## Wie es funktioniert

Claude Code ruft vor jedem Tool-Aufruf registrierte Hooks auf. guard prüft den Aufruf gegen `guard.rules.json`:

- **Exit 0** → erlaubt (optional mit Hinweis an Claude)
- **Exit 2** → blockiert; die Begründung wird Claude gezeigt, damit es eine sichere Alternative wählt

Alle Regeln liegen in `guard.rules.json` im Projekt-Root — versionierbar, reviewbar, pro Projekt anpassbar.

## Setup

```bash
cd dein-projekt
npx @elevenworks/guard init
# Claude Code neustarten
```

`init` verändert nichts Destruktives: bestehende `settings.json` wird gemergt, ein vorhandenes Regelwerk nie überschrieben. `init` trägt zwei maschinenlokale Dateien automatisch in `.gitignore` ein: `.claude/guard-audit.jsonl` (das Compliance-Log) und `.claude/guard-verified.json` (das Verifikations-Siegel, siehe unten) — beide gehören nicht ins Repo.

## Audit-Log

`.claude/guard-audit.jsonl` — ein Event pro Zeile:

```json
{"ts":"2026-07-09T14:31:02.114Z","event":"blocked","type":"path","tool":"Read","target":".env","ruleId":"path.dotenv","rule":"**/.env"}
```

Wird von `guard init` automatisch in `.gitignore` aufgenommen (zusammen mit dem Siegel `.claude/guard-verified.json`). Zusammenfassung: `npx @elevenworks/guard status`

## Modus: enforce vs. monitor

`guard.rules.json` steuert per `"mode"`, ob eine Übereinstimmung tatsächlich blockiert oder nur protokolliert wird:

```json
{ "mode": "enforce" }
```

- **`enforce`** (Default) — geschützte Pfade und gefährliche Kommandos werden blockiert (Exit 2), Claude bekommt die Begründung und muss eine sichere Alternative wählen.
- **`monitor`** — nichts wird blockiert. Jede Übereinstimmung, die im `enforce`-Modus geblockt worden wäre, wird stattdessen als `would-block` ins Audit-Log geschrieben und das Tool läuft durch (Exit 0). `guard status` und `guard report` zeigen diese würde-blockiert-Zahl getrennt von den tatsächlich blockierten Events.

`monitor` ist **audit-only** — reines Beobachten, kein Schutz. Es existiert als Adoptionspfad: Teams, die guard neu einführen, können erst sehen, welche Regeln in ihrer Codebasis überhaupt greifen würden (False-Positives, unerwartete Treffer), bevor sie scharf schalten. Für den eigentlichen Schutz gehört `enforce` production-seitig gesetzt.

Die Injection-Erkennung (`PostToolUse`) ist von diesem Schalter unabhängig — sie **blockt nie**, in keinem Modus, sondern warnt nur (siehe „Ehrliche Grenzen" unten). `mode` betrifft ausschließlich die Durchsetzung von Pfad- und Kommando-Regeln in `pretool.js`.

## Ist guard wirklich scharf? — Banner & `guard verify`

Zwei Belege, die zusammen die ganze Frage beantworten:

**1. Das Banner beim Session-Start.** Startest du Claude Code ganz normal (`claude`),
meldet sich guard selbst:

```
[guard] aktiv · 49 Regeln · enforce · zuletzt verifiziert: 13.07. 14:23 ✓
```

Dieses Banner **kann nur erscheinen, wenn Claude Code guard tatsächlich ausführt** —
es ist damit der Beweis für die *Verdrahtung*. Bleibt es aus, läuft guard nicht.

**2. `guard verify` — der Selbsttest.**

```bash
npx @elevenworks/guard verify
```

Er fährt den **echten installierten Hook** mit deinen **echten Regeln** und prüft:
Hooks registriert · Regelwerk geladen · **blockt Secrets** (`.env`) · **blockt nicht
pauschal** (`.env.example` bleibt erlaubt) · Audit-Log schreibbar. Er läuft in einem
Wegwerf-Verzeichnis — **dein Compliance-Log bleibt sauber**, es entstehen keine
synthetischen Test-Events.

Bei Erfolg schreibt er ein **Siegel** (`.claude/guard-verified.json`) mit einem
Fingerabdruck über **Verdrahtung + Regeln + Hooks**. Ändert sich eines davon —
etwa weil jemand den Block-Hook aus `settings.json` entfernt oder `pretool.js`
entschärft —, wird das Siegel ungültig und das Banner sagt es dir:

```
[guard] aktiv · 49 Regeln · enforce · ⚠ Verdrahtung/Regeln/Hooks seit der Verifikation geändert
```

**Das Banner behauptet nie mehr, als getestet wurde.** Läuft guard nur im
Beobachten-Modus, sagt es auch das — bei jedem Start:

```
[guard] aktiv · 49 Regeln · monitor · …  ⚠ monitor-Modus — beobachtet nur, blockt nicht
```

**Im Team:** Regeln, Hooks und Verdrahtung liegen im Repo — das Siegel nicht
(es ist maschinenlokal). Wer das Repo frisch klont, sieht daher beim ersten Start
`⚠ nicht verifiziert` und führt einmal `guard verify` aus. Das ist Absicht: ein
mitgeliefertes „verifiziert ✓" würde nur bezeugen, dass es *irgendwo* mal lief.

**Nach einem guard-Upgrade** `npx @elevenworks/guard init` erneut ausführen — das
frischt die Hooks auf und verifiziert gleich neu.

## Ehrliche Grenzen

- **Hooks sind eine Schutzschicht, keine Sandbox.** Wer Claude Code mit `--dangerously-skip-permissions` und ohne Hooks startet, umgeht alles. guard schützt vor Versehen und Injection-Mustern — für harte Isolation gehört eine Container-/Egress-Schicht dazu.
- **PII-Erkennung ist Regex-basiert.** Sie fängt strukturierte Muster (IBAN, Keys, E-Mail), keine Freitext-Namen. Für echte Datenbank-Arbeit: [doppel].
- **Dynamisch zusammengebaute Pfade entkommen der Denylist.** Wer einen Secret-Pfad zur Laufzeit zusammensetzt (`open('.e'+'nv')`, `f=.en; cat ${f}v`), umgeht die statische Muster-Erkennung. Das ist eine prinzipielle Grenze regex-basierter Denylists — im Testkorpus als `known-gap` markiert und bewusst dokumentiert, nicht wegmarketet. Solche Laufzeit-Konstruktionen erkennt nur eine Ausführungs-Sandbox, keine statische Regel.
- **Fail-open bei Hook-Fehlern.** Ein Hook, der abstürzt oder fehlerhaften Input bekommt, lässt den Workflow bewusst durch (Exit 0), statt ihn zu blockieren — guard soll nie zwischen Claude und die eigentliche Arbeit treten. Der Preis dieser Entscheidung: ein Hook, der nicht läuft, schützt in diesem Moment auch nicht.
- **Injection-Erkennung ist eine Heuristik, keine Garantie.** Sie fängt bekannte Phrasen (`ignore previous instructions`, `<!-- SYSTEM: ... -->`, …) im gelesenen Inhalt und **warnt** — sie **blockt nicht**, weil Claude den legitimen Inhalt trotzdem braucht (z. B. die echte Bug-Beschreibung in derselben Datei). Umschriebene/paraphrasierte Injektionen entkommen der Phrasenliste (im Testkorpus als `known-gap` markiert). Der harte Schutz bleibt die geblockte Folgeaktion: selbst wenn eine Injection Claude dazu bringt, ein Secret lesen oder senden zu wollen, blockiert `pretool.js` das tatsächlich.
- **Das Siegel schützt gegen Drift, nicht gegen Sabotage.** Es erkennt, wenn Verdrahtung, Regeln oder Hooks sich geändert haben — also den realistischen Fall „jemand hat etwas verstellt und es vergessen". Wer als Angreifer bereits Schreibrechte auf der Maschine hat, kann Hooks **und** Siegel gemeinsam fälschen. Dagegen hilft kein Hook, sondern nur eine Sandbox. Ebenso gilt weiterhin: `verify` beweist, dass der Hook blockt — dass Claude Code ihn *aufruft*, beweist erst das Banner. Erst beide zusammen ergeben den vollen Beleg.

## Lizenz

MIT — Open Core. Zentrale Policy-Verwaltung, Dashboards und Compliance-Reports: [elevenworks.io](https://elevenworks.io)
