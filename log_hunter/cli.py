"""Komut satırı arayüzü.

Kullanım:
    log-hunter /var/log/auth.log --html rapor.html
    log-hunter /var/log --sarif sonuc.sarif --min-severity high --fail-on-alert

Çıkış kodları:  0 = temiz | 1 = uyarı var (--fail-on-alert ile) | 2 = hata / eksik tarama
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import SEVERITY_RANK
from .report import to_html, to_json, to_sarif
from .rules import SEVERITIES, RuleError, load_rules
from .scanner import Scanner


def _write(path: str, content: str) -> None:
    # Rapor çıktısı UTF-8; var olan dosyanın üzerine yazar.
    Path(path).write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="log-hunter", description="Kural tabanlı log tarama motoru (auth.log)")
    parser.add_argument("paths", nargs="+", help="Log dosyası veya klasör(ler) (.gz desteklenir)")
    parser.add_argument("--rules", default=None, help="Kural klasörü (varsayılan: paketle gelen kurallar)")
    parser.add_argument("--year", type=int, help="Log yılı (syslog'ta yıl yok; varsayılan: bu yıl)")
    parser.add_argument("--html", metavar="DOSYA", help="HTML rapor yolu")
    parser.add_argument("--json", metavar="DOSYA", help="JSON rapor yolu")
    parser.add_argument("--sarif", metavar="DOSYA", help="SARIF rapor yolu (GitHub Code Scanning)")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="low",
                        help="Bu önem düzeyinin altındaki uyarıları gösterme")
    parser.add_argument("--max-file-mb", type=int, default=200,
                        help="Dosya başına en fazla MB (gz için açılmış boyut; varsayılan 200)")
    parser.add_argument("--fail-on-alert", action="store_true",
                        help="Uyarı varsa çıkış kodu 1 (CI/otomasyon için)")
    args = parser.parse_args(argv)

    if args.max_file_mb < 1:
        parser.error("--max-file-mb en az 1 olmalı")

    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        # Ayrıntılı traceback yerine kısa hata: çıktıya sızıntıyı azaltır.
        print(f"Hata: {exc}", file=sys.stderr)
        return 2

    scanner = Scanner(rules, year=args.year, max_file_bytes=args.max_file_mb * 1024 * 1024)
    result = scanner.scan(args.paths)

    # Önem filtresi hem çıktıyı hem çıkış kodunu etkiler
    floor = SEVERITY_RANK[args.min_severity]
    alerts = [a for a in result.alerts if SEVERITY_RANK[a.severity] >= floor]

    print(f"{len(result.files)} dosya, {result.event_count} olay, {len(rules)} kural, "
          f"{len(alerts)} uyarı ({result.seconds:.2f} sn):")
    for a in alerts:
        print(f"  [{a.severity.upper():8}] {a.rule_id} {a.title} | anahtar={a.key} "
              f"adet={a.count} mitre={a.mitre}")
    for msg in result.skipped:
        print(f"Atlandı: {msg}", file=sys.stderr)
    for msg in result.errors:
        print(f"Hata: {msg}", file=sys.stderr)
    if not result.files and not result.errors:
        print("Hata: taranacak log dosyası bulunamadı", file=sys.stderr)
        return 2

    try:
        source = ", ".join(args.paths)
        if args.html:
            _write(args.html, to_html(alerts, source=source))
        if args.json:
            _write(args.json, to_json(alerts))
        if args.sarif:
            _write(args.sarif, to_sarif(alerts))
    except OSError as exc:
        print(f"Hata: rapor yazılamadı: {exc}", file=sys.stderr)
        return 2

    if result.errors:
        return 2          # Eksik tarama "temiz" sayılmasın
    return 1 if (alerts and args.fail_on_alert) else 0
