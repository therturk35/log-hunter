"""Rapor üretimi: JSON ve tek dosyalık (self-contained) HTML.

GÜVENLİK (önemli): Log içeriği saldırgan kontrolündedir. Örneğin bir saldırgan
kullanıcı adı olarak '<script>...</script>' deneyebilir. Raporu açan analist
tarayıcısında kod çalışmasın diye HER log kaynaklı değer html.escape'ten geçer.
Ayrıca sayfaya katı bir Content-Security-Policy eklenir (script yasak, dış
kaynak yok).
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime
from typing import Optional

from .models import Alert

CSS = """
body{font-family:system-ui,sans-serif;margin:2rem;background:#0f172a;color:#e2e8f0}
h1{margin-bottom:.2rem} .meta{color:#94a3b8;margin-bottom:1.5rem}
.summary span{display:inline-block;margin-right:.6rem;padding:.2rem .7rem;border-radius:.4rem;font-weight:600}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th,td{border-bottom:1px solid #334155;padding:.5rem;text-align:left;vertical-align:top}
.badge{padding:.15rem .5rem;border-radius:.3rem;font-weight:700;color:#0f172a}
.critical{background:#f87171}.high{background:#fb923c}.medium{background:#facc15}.low{background:#4ade80}
pre{background:#1e293b;padding:.6rem;border-radius:.4rem;overflow-x:auto;white-space:pre-wrap}
a{color:#7dd3fc}
"""


def _e(value: object) -> str:
    """Tek yerden HTML kaçışı: log kaynaklı hiçbir değer ham basılmaz."""
    return html.escape(str(value), quote=True)


def to_json(alerts: list[Alert]) -> str:
    """Uyarıları JSON metni olarak döndürür (SIEM/otomasyon için)."""
    data = [
        {
            "rule_id": a.rule_id, "title": a.title, "severity": a.severity,
            "mitre": a.mitre, "key": a.key, "count": a.count,
            "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat(),
            "evidence": [{"file": e.source, "line": e.line_no, "raw": e.raw} for e in a.evidence],
        }
        for a in alerts
    ]
    return json.dumps(data, ensure_ascii=False, indent=2)


# SARIF: GitHub Code Scanning, VS Code vb. araçların okuduğu standart bulgu formatı.
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
# GitHub'ın önem sıralaması için kullandığı sayısal skor (0-10)
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def to_sarif(alerts: list[Alert]) -> str:
    """Uyarıları SARIF 2.1.0 belgesi olarak döndürür."""
    from . import __version__  # Döngüsel içe aktarmayı önlemek için burada

    rules: dict[str, dict] = {}
    results = []
    for a in alerts:
        rules.setdefault(a.rule_id, {
            "id": a.rule_id,
            "name": a.rule_id,
            "shortDescription": {"text": a.title},
            "fullDescription": {"text": a.description or a.title},
            "helpUri": "https://attack.mitre.org/techniques/" + a.mitre.replace(".", "/") + "/",
            "properties": {"tags": ["security", a.mitre], "security-severity": _SARIF_SCORE[a.severity]},
        })
        result = {
            "ruleId": a.rule_id,
            "level": _SARIF_LEVEL[a.severity],
            "message": {"text": f"{a.title} (anahtar: {a.key}, adet: {a.count})"},
        }
        # Konum: kanıt olarak eklenen ilk olayın dosyası ve satırı
        first = next((e for e in a.evidence if e.source), None)
        if first:
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": first.source},
                "region": {"startLine": first.line_no},
            }}]
        results.append(result)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "log-hunter", "version": __version__,
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


def to_html(alerts: list[Alert], source: str, generated_at: Optional[datetime] = None) -> str:
    """Uyarılardan tek dosyalık HTML rapor üretir."""
    generated_at = generated_at or datetime.now()
    counts = Counter(a.severity for a in alerts)

    summary = "".join(
        f'<span class="badge {sev}">{_e(sev)}: {counts.get(sev, 0)}</span>'
        for sev in ("critical", "high", "medium", "low")
    )

    rows = []
    for a in alerts:
        # MITRE kimliği rules.py'de regex ile doğrulandı; yine de kaçışlıyoruz.
        mitre_url = "https://attack.mitre.org/techniques/" + a.mitre.replace(".", "/") + "/"
        evidence = "\n".join(
            f"{e.source + ':' if e.source else ''}L{e.line_no}: {e.raw}" for e in a.evidence)
        rows.append(
            "<tr>"
            f'<td><span class="badge {_e(a.severity)}">{_e(a.severity)}</span></td>'
            f"<td>{_e(a.rule_id)}<br>{_e(a.title)}</td>"
            f'<td><a href="{_e(mitre_url)}" rel="noopener noreferrer">{_e(a.mitre)}</a></td>'
            f"<td>{_e(a.key)}</td>"
            f"<td>{_e(a.count)}</td>"
            f"<td>{_e(a.first_seen)}<br>{_e(a.last_seen)}</td>"
            f"<td><details><summary>kanıt ({len(a.evidence)})</summary>"
            f"<pre>{_e(evidence)}</pre></details></td>"
            "</tr>"
        )

    body = "".join(rows) or '<tr><td colspan="7">Uyarı yok.</td></tr>'

    return (
        "<!doctype html><html lang='tr'><head><meta charset='utf-8'>"
        # Script yok, dış kaynak yok: sadece inline stil.
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>log-hunter raporu</title>"
        f"<style>{CSS}</style></head><body>"
        "<h1>log-hunter raporu</h1>"
        f"<div class='meta'>Kaynak: {_e(source)} &middot; Üretim: {_e(generated_at.strftime('%Y-%m-%d %H:%M:%S'))}"
        f" &middot; Toplam uyarı: {len(alerts)}</div>"
        f"<div class='summary'>{summary}</div>"
        "<table><thead><tr><th>Önem</th><th>Kural</th><th>MITRE</th><th>Anahtar</th>"
        "<th>Adet</th><th>Zaman</th><th>Kanıt</th></tr></thead>"
        f"<tbody>{body}</tbody></table></body></html>"
    )
