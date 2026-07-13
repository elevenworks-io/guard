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
| Audit-Log | Jede Entscheidung als JSONL — lückenlos und lokal | alle |

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

`init` führt am Ende automatisch den Selbsttest (`guard verify`) aus und **kann mit Exit 1 fehlschlagen** (z. B. wenn eine Regel entschärft wurde oder die Verdrahtung unvollständig ist). Die Installation wird dabei nicht zurückgerollt — Hooks, Regelwerk und `settings.json` bleiben bestehen, die Fehlerursache steht in der Ausgabe. Beheben, dann erneut: `guard verify`.

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
[guard] aktiv · 49 Regeln · enforce · zuletzt verifiziert: 13.07. 14:23 ✓ · 49/49 Regeln probiert
```

Dieses Banner **kann nur erscheinen, wenn Claude Code guard tatsächlich ausführt** —
es ist damit der Beweis für die *Verdrahtung*. Bleibt es aus, läuft guard nicht.

**2. `guard verify` — der Selbsttest.**

```bash
npx @elevenworks/guard verify
```

Er fährt den **echten installierten Hook** mit deinen **echten Regeln** — und zwar
für **jede einzelne konfigurierte Regel**, nicht nur für zwei Stichproben. Jede
Pfad-, Kommando-, PII- und Injection-Regel bekommt ein Beweismuster vorgelegt, und
`verify` prüft, ob dabei tatsächlich das erwartete Audit-Event mit der passenden
Regel-ID feuert — das ist die Garantie, die guard tatsächlich einlöst: nicht
woher ein Muster stammt, sondern dass es die Regel nachweislich zum Feuern
bringt:

```
✓ Hooks registriert       PostToolUse, PreToolUse, SessionStart, UserPromptSubmit
✓ Regelwerk geladen       49 Regeln · Modus: enforce
✓ Pfad-Regeln             21/21 probiert
✓ Kommando-Regeln         14/14 probiert
✓ PII-Muster               9/9 probiert
✓ Injection-Muster         5/5 probiert
✓ Blockt Secrets          .env → blockiert
✓ Blockt nicht pauschal   .env.example → erlaubt
✓ Audit-Log schreibbar    .claude/guard-audit.jsonl

✓ 49/49 Regeln nachweislich scharf.
```

Er läuft dabei in einem Wegwerf-Verzeichnis — **dein Compliance-Log bleibt
sauber**, es entstehen keine synthetischen Test-Events.

**Was das beweist — und was nicht.** Jede Regel mit einem Testmuster ist
nachweislich scharf: `verify` hat sie tatsächlich zum Feuern gebracht, nicht nur
geladen. Eine eigene Regel ohne Testmuster (du hast selbst eine hinzugefügt) wird
als **ungeprüft** gemeldet — sichtbar, nie stillschweigend als Erfolg gezählt:

```
⚠ 3 eigene Regeln ohne Testmuster — nicht probiert: cmd.mine, path.mine, pii.mine
✓ 49/52 Regeln nachweislich scharf.
```

Gib ihr ein eigenes `"sample"`-Feld in `guard.rules.json` mit, um sie ebenfalls zu
beweisen. **Was `verify` NICHT beweist:** dass das Muster einer Regel *semantisch*
die richtige Wahl für dein Bedrohungsmodell ist — nur, dass die Regel wie
konfiguriert tatsächlich zieht.

Er schreibt **immer** ein **Siegel** (`.claude/guard-verified.json`) — auch bei
Fehlschlag (`ok: false`). Das ist Absicht: erst dadurch kann das Banner beim
nächsten Session-Start ehrlich "FEHLGESCHLAGEN" statt "nicht verifiziert"
melden. Das Siegel trägt einen Fingerabdruck über **Verdrahtung + Regeln +
Hooks** sowie den erreichten Deckungsgrad. Ändert sich eines davon — etwa weil
jemand den Block-Hook aus `settings.json` entfernt oder `pretool.js`
entschärft —, wird das Siegel ungültig und das Banner sagt es dir:

```
[guard] aktiv · 49 Regeln · enforce · ⚠ Verdrahtung/Regeln/Hooks seit der Verifikation geändert
```

**Wo guard nachsieht.** `guard init` registriert die Hooks ausschließlich in
`.claude/settings.json` (Projektebene), und Banner wie `verify` prüfen auch
nur dort. Hooks, die in einer anderen Settings-Ebene liegen —
`.claude/settings.local.json` oder `~/.claude/settings.json` — sieht das
Banner **nicht**. Das ist ein Unter-, kein Überclaim (sicher in die falsche
Richtung), kann aber überraschen: guard läuft dann eventuell trotzdem (Claude
Code merged alle Ebenen), das Banner meldet aber fälschlich "es wird derzeit
NICHTS blockiert".

**Das Banner behauptet nie mehr, als getestet wurde.** Läuft guard nur im
Beobachten-Modus, sagt es auch das — bei jedem Start:

```
[guard] aktiv · 49 Regeln · monitor · …  ⚠ monitor-Modus — beobachtet nur, blockt nicht
```

Und es trägt den Deckungsgrad aus dem letzten `verify`-Lauf sichtbar mit:

```
[guard] aktiv · 49 Regeln · enforce · zuletzt verifiziert: 13.07. 14:23 ✓ · 49/49 Regeln probiert
```

Ist das Audit-Log per `audit.enabled: false` abgeschaltet, sagt guard auch das —
denn dann entsteht überhaupt kein Nachweis:

```
[guard] aktiv · 49 Regeln · enforce · zuletzt verifiziert: … ✓  ⚠ Audit-Log deaktiviert — kein Nachweis
```

**Im Team:** Regeln, Hooks und Verdrahtung liegen im Repo — das Siegel nicht.
Es ist **an die Maschine gebunden**: neben Fingerabdruck und Projektpfad trägt es
eine zufällige `installId`, die außerhalb des Repos liegt
(`~/.config/elevenworks-guard/machine-id`). Selbst ein versehentlich committetes
Siegel ist damit wertlos — auf einer anderen Maschine (auch im selben Container,
mit identischem Hostnamen und Pfad) meldet das Banner schlicht `⚠ nicht verifiziert`.
Wer das Repo frisch klont, führt daher einmal `guard verify` aus. Das ist Absicht:
ein mitgeliefertes „verifiziert ✓" würde nur bezeugen, dass es *irgendwo* mal lief.

**Nach einem guard-Upgrade** `npx @elevenworks/guard init` erneut ausführen — das
frischt die Hooks auf und verifiziert gleich neu.

## Ehrliche Grenzen

- **Hooks sind eine Schutzschicht, keine Sandbox.** `--dangerously-skip-permissions` bzw. `bypassPermissions` hebeln guard **nicht** aus: `PreToolUse`-Hooks feuern laut offizieller Claude-Code-Doku *vor* der Permission-Mode-Prüfung, ein Hook mit `permissionDecision: "deny"` blockt also auch im Bypass-Modus — mit dem echten CLI gegen einen `.env`-Read getestet und bestätigt geblockt. Ein Entwickler kann guard also nicht einfach per Flag abschalten. Was guard tatsächlich abschaltet: `"disableAllHooks": true` in `.claude/settings.json`, oder die Hooks gar nicht erst zu installieren — dann läuft guard nicht, es erscheint kein Verifizierungs-Banner beim Start (die *Abwesenheit* des Banners ist selbst das Signal), und `guard verify` schlägt jetzt bei `disableAllHooks` explizit fehl statt grün zu melden. Was guard trotzdem nicht ist: eine Sandbox. guard bewacht Claude Codes Tool-Aufrufe — nicht einen Prozess, der bereits ausgebrochen ist (z. B. beliebiger Code aus einem Build-Skript oder einer kompromittierten Abhängigkeit). Für harte Isolation gehört weiterhin eine Container-/Egress-Schicht dazu.
- **PII-Erkennung ist Regex-basiert.** Sie fängt strukturierte Muster (IBAN, Keys, E-Mail), keine Freitext-Namen. Für echte Datenbank-Arbeit: [doppel].
- **Dynamisch zusammengebaute Pfade entkommen der Denylist.** Wer einen Secret-Pfad zur Laufzeit zusammensetzt (`open('.e'+'nv')`, `f=.en; cat ${f}v`), umgeht die statische Muster-Erkennung. Das ist eine prinzipielle Grenze regex-basierter Denylists — im Testkorpus als `known-gap` markiert und bewusst dokumentiert, nicht wegmarketet. Solche Laufzeit-Konstruktionen erkennt nur eine Ausführungs-Sandbox, keine statische Regel.
- **Fail-open bei Hook-Fehlern.** Ein Hook, der abstürzt oder fehlerhaften Input bekommt, lässt den Workflow bewusst durch (Exit 0), statt ihn zu blockieren — guard soll nie zwischen Claude und die eigentliche Arbeit treten. Der Preis dieser Entscheidung: ein Hook, der nicht läuft, schützt in diesem Moment auch nicht.
- **Injection-Erkennung ist eine Heuristik, keine Garantie.** Sie fängt bekannte Phrasen (`ignore previous instructions`, `<!-- SYSTEM: ... -->`, …) im gelesenen Inhalt und **warnt** — sie **blockt nicht**, weil Claude den legitimen Inhalt trotzdem braucht (z. B. die echte Bug-Beschreibung in derselben Datei). Umschriebene/paraphrasierte Injektionen entkommen der Phrasenliste (im Testkorpus als `known-gap` markiert). Der harte Schutz bleibt die geblockte Folgeaktion: selbst wenn eine Injection Claude dazu bringt, ein Secret lesen oder senden zu wollen, blockiert `pretool.js` das tatsächlich.
- **Das Siegel schützt gegen Drift, nicht gegen Sabotage.** Es erkennt, wenn Verdrahtung, Regeln oder Hooks sich geändert haben — also den realistischen Fall „jemand hat etwas verstellt und es vergessen". Wer als Angreifer bereits Schreibrechte auf der Maschine hat, kann Hooks **und** Siegel gemeinsam fälschen. Dagegen hilft kein Hook, sondern nur eine Sandbox. Ebenso gilt weiterhin: `verify` beweist, dass der Hook blockt — dass Claude Code ihn *aufruft*, beweist erst das Banner. Erst beide zusammen ergeben den vollen Beleg.
- **Das Audit-Log ist nicht manipulationssicher.** Es ist eine gewöhnliche Datei. Wer Schreibrechte auf der Maschine hat, kann Einträge ändern oder löschen — und weder `guard report` noch `guard status` würden das bemerken. Das Log belegt **lückenlos, was guard entschieden hat**; es beweist **nicht**, dass niemand nachträglich daran war. **„Revisionssicher" im Sinne der GoBD ist es ausdrücklich nicht** — dafür braucht es einen externen, unveränderlichen Anker (eine Hash-Kette allein genügt nicht: wer eine Zeile entfernt, kann sie mit einem öffentlichen Algorithmus einfach neu berechnen).

## Lizenz

MIT — Open Core. Zentrale Policy-Verwaltung, Dashboards und Compliance-Reports: [elevenworks.io](https://elevenworks.io)
