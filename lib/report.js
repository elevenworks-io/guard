"use strict";
// Erzeugt aus Audit-Log + Regelwerk ein hässliches-aber-echtes Markdown-Protokoll.
function countRules(rules) {
  return (rules.blockedPaths?.length || 0) + (rules.blockedCommands?.length || 0) + (rules.piiPatterns?.length || 0) + (rules.injectionPatterns?.length || 0);
}
function buildReport({ auditLines, rules, now }) {
  const blocked = auditLines.filter((e) => e.event === "blocked");
  const warned = auditLines.filter((e) => e.event === "warned");
  const injections = auditLines.filter((e) => e.event === "injection-detected");
  const allowed = auditLines.filter((e) => e.event === "allowed");
  const times = auditLines.map((e) => e.ts).filter(Boolean).sort();
  const start = times[0] || now;
  const end = times[times.length - 1] || now;

  const byRule = {};
  for (const e of blocked) {
    const id = e.ruleId || (e.findings || []).map((f) => f.ruleId).find(Boolean) || "(unbekannt)";
    byRule[id] = (byRule[id] || 0) + 1;
  }
  const lines = [];
  lines.push("# guard — Nachweis");
  lines.push("");
  lines.push(`**Erstellt:** ${now}`);
  lines.push(`**Session-Zeitraum:** ${start} → ${end}`);
  lines.push(`**Modus:** ${rules.mode || "enforce"}`);
  lines.push(`**Regeln aktiv:** ${countRules(rules)}`);
  lines.push("");
  lines.push("## Zusammenfassung");
  lines.push(`- Ereignisse gesamt: ${auditLines.length}`);
  lines.push(`- **${blocked.length} blockiert**, ${injections.length} Injection erkannt, ${warned.length} gewarnt, ${allowed.length} erlaubt`);
  lines.push("");
  lines.push("## Blockierte Zugriffe nach Regel");
  if (Object.keys(byRule).length === 0) {
    lines.push("_Keine blockierten Ereignisse in dieser Session._");
  } else {
    lines.push("| Regel-ID | Anzahl |");
    lines.push("|---|---|");
    for (const [id, n] of Object.entries(byRule).sort((a, b) => b[1] - a[1])) {
      lines.push(`| \`${id}\` | ${n} |`);
    }
  }
  lines.push("");
  lines.push("## Aktive Regelklassen");
  lines.push(`- Geschützte Pfade: ${rules.blockedPaths?.length || 0}`);
  lines.push(`- Kommando-Regeln: ${rules.blockedCommands?.length || 0}`);
  lines.push(`- PII-Muster: ${rules.piiPatterns?.length || 0}`);
  lines.push(`- Injection-Muster: ${rules.injectionPatterns?.length || 0}`);
  lines.push("");
  lines.push("_Generiert von @elevenworks/guard. Datengrundlage: `.claude/guard-audit.jsonl`._");
  return lines.join("\n");
}
module.exports = { buildReport };
