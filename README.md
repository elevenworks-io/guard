# @elevenworks/guard

Der Sicherheitsgurt für Claude Code. Secret-Blocker, Command-Denylist, PII-Erkennung, Audit-Log — installiert in einer Minute.

```
npx @elevenworks/guard init
✓ 44 Regeln aktiv
```

## Was guard macht

| Schutz | Mechanik | Hook |
|---|---|---|
| Secrets unsichtbar | `.env`, Keys, Credentials — Lese-Zugriff wird blockiert | PreToolUse |
| Gefährliche Kommandos | `rm -rf`, Force-Push, `curl \| sh`, `DROP TABLE`, … | PreToolUse |
| PII-Erkennung | E-Mail, IBAN, Steuer-ID, API-Keys im Prompt | UserPromptSubmit |
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

`init` verändert nichts Destruktives: bestehende `settings.json` wird gemergt, ein vorhandenes Regelwerk nie überschrieben.

## Audit-Log

`.claude/guard-audit.jsonl` — ein Event pro Zeile:

```json
{"ts":"2026-07-09T14:31:02.114Z","event":"blocked","type":"path","tool":"Read","target":".env","ruleId":"path.dotenv","rule":"**/.env"}
```

In `.gitignore` aufnehmen. Zusammenfassung: `npx @elevenworks/guard status`

## Ehrliche Grenzen (v0.1)

- **Hooks sind eine Schutzschicht, keine Sandbox.** Wer Claude Code mit `--dangerously-skip-permissions` und ohne Hooks startet, umgeht alles. guard schützt vor Versehen und Injection-Mustern — für harte Isolation gehört eine Container-/Egress-Schicht dazu.
- **PII-Erkennung ist Regex-basiert.** Sie fängt strukturierte Muster (IBAN, Keys, E-Mail), keine Freitext-Namen. Für echte Datenbank-Arbeit: [doppel].
- **Dynamisch zusammengebaute Pfade entkommen der Denylist.** Wer einen Secret-Pfad zur Laufzeit zusammensetzt (`open('.e'+'nv')`, `f=.en; cat ${f}v`), umgeht die statische Muster-Erkennung. Das ist eine prinzipielle Grenze regex-basierter Denylists — im Testkorpus als `known-gap` markiert und bewusst dokumentiert, nicht wegmarketet. Solche Laufzeit-Konstruktionen erkennt nur eine Ausführungs-Sandbox, keine statische Regel.
- **Fail-open bei Hook-Fehlern.** Ein kaputter Hook blockiert v0.1 nicht den Workflow. Enforce-Modus mit fail-closed kommt in v0.2.

## Lizenz

MIT — Open Core. Zentrale Policy-Verwaltung, Dashboards und Compliance-Reports: [elevenworks.io](https://elevenworks.io)
