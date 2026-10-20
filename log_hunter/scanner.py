"""Tarama motoru: dosya/klasör keşfi + okuma + ayrıştırma + kural değerlendirme.

Kütüphane olarak kullanım:
    from log_hunter import Scanner, load_rules
    result = Scanner(load_rules()).scan(["/var/log"])
    for alert in result.alerts: ...

Güvenlik tasarımı:
  * Klasör taramada sembolik bağlar TAKİP EDİLMEZ (klasör dışına kaçışı önler).
  * Dosya sayısı ve dosya başına bayt sınırı vardır (kaynak tüketimi / zip-bomb).
  * Okunamayan veya sınırı aşan dosya 'errors' içinde bildirilir; böylece
    eksik tarama "temiz" sonucu gibi görünmez.
"""

from __future__ import annotations

import os
import re
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .engine import evaluate
from .models import Alert, Event
from .parsers import DEFAULT_MAX_BYTES, PARSERS, ScanLimitError, read_lines
from .rules import Rule

# Klasör taramasında dikkate alınacak dosya adları:
# auth.log, secure, *.log  (+ döndürülmüş .1 ve .gz sürümleri)
LOG_NAME_RE = re.compile(r"^(auth\.log|secure|.+\.log)(\.\d+)?(\.gz)?$")


@dataclass
class ScanResult:
    files: list[str] = field(default_factory=list)      # Başarıyla taranan dosyalar
    event_count: int = 0                                 # Okunan toplam olay
    alerts: list[Alert] = field(default_factory=list)   # Önem + zamana göre sıralı
    errors: list[str] = field(default_factory=list)     # Taramayı eksik bırakan sorunlar
    skipped: list[str] = field(default_factory=list)    # Bilerek atlananlar (bilgi amaçlı)
    seconds: float = 0.0


class Scanner:
    def __init__(self, rules: list[Rule], parser: str = "auth", year: int | None = None,
                 max_file_bytes: int = DEFAULT_MAX_BYTES, max_files: int = 10_000):
        if parser not in PARSERS:
            raise ValueError(f"Bilinmeyen parser: {parser} (mevcut: {sorted(PARSERS)})")
        self.rules = rules
        self.parse = PARSERS[parser]
        self.year = year
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files

    def _discover(self, paths: Iterable[str | Path], result: ScanResult) -> Iterator[Path]:
        """Verilen dosya/klasörlerden taranacak dosyaları sırayla üretir."""
        seen: set[Path] = set()
        count = 0

        def accept(f: Path) -> bool:
            nonlocal count
            real = f.resolve()
            if real in seen:
                return False          # Aynı dosya iki kez verilmişse tekrar tarama
            if count >= self.max_files:
                result.skipped.append(f"{f}: dosya sayısı sınırı aşıldı ({self.max_files})")
                return False
            seen.add(real)
            count += 1
            return True

        for raw in paths:
            p = Path(raw)
            if p.is_dir():
                # followlinks=False: sembolik bağlı klasörlere inilmez
                for root, dirs, names in os.walk(p, followlinks=False):
                    dirs.sort()
                    for name in sorted(names):
                        f = Path(root) / name
                        if not LOG_NAME_RE.match(name):
                            continue
                        if f.is_symlink():
                            result.skipped.append(f"{f}: sembolik bağ atlandı")
                            continue
                        if accept(f):
                            yield f
            elif p.is_file():
                if accept(p):          # Açıkça verilen dosya ad filtresine takılmaz
                    yield p
            else:
                result.errors.append(f"{p}: bulunamadı")

    def scan(self, paths: Iterable[str | Path]) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()
        events: list[Event] = []

        for f in self._discover(paths, result):
            try:
                # Düz dosyada okumadan önce ucuz boyut kontrolü
                if not str(f).endswith(".gz") and f.stat().st_size > self.max_file_bytes:
                    raise ScanLimitError(f"boyut sınırı aşıldı (> {self.max_file_bytes // (1024 * 1024)} MB)")
                evs = self.parse(read_lines(f, self.max_file_bytes), self.year, f.as_posix())
            except (OSError, EOFError, zlib.error, ScanLimitError) as exc:
                result.errors.append(f"{f}: {exc}")
                continue
            result.files.append(f.as_posix())
            events.extend(evs)

        # Dosyalar arası korelasyon için tüm olaylar tek zaman çizelgesinde birleşir
        # (örn. brute-force'un yarısı auth.log, yarısı auth.log.1 içindeyse yine yakalanır).
        events.sort(key=lambda e: (e.ts, e.source, e.line_no))
        result.event_count = len(events)
        result.alerts = evaluate(events, self.rules)
        result.seconds = time.perf_counter() - start
        return result
