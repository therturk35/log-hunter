"""auth.log (syslog formatı) okuma ve ayrıştırma.

Akış:  dosya --(read_lines)--> güvenli satır akışı
       satır --(SYSLOG_RE)--> zaman/host/process/mesaj
             --(PATTERNS)---> event_type, user, source_ip

Güvenlik notları:
  * Log dosyası GÜVENİLMEZ girdidir (saldırgan log içeriğini etkileyebilir).
    Bu yüzden satır uzunluğu ve toplam okunan bayt sınırlıdır; regex'ler
    basit/çapalıdır; bozuk baytlar 'replace' ile işlenir (çökme olmasın diye).
  * .gz dosyalarda SIKIŞTIRILMIŞ boyut değil, AÇILMIŞ boyut sınırlanır
    (zip-bomb koruması).
  * Dosya hiçbir zaman çalıştırılmaz / eval edilmez; sadece metin olarak okunur.
"""

from __future__ import annotations

import gzip
import re
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

from .models import Event

# Syslog ay kısaltmaları. strptime('%b') kullanmıyoruz çünkü sistem diline
# (locale) bağlı çalışır; Türkçe sistemde "Oct" yerine "Eki" bekleyebilir.
MONTHS = {
    name: i
    for i, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

# Aşırı uzun satırlar bellek/regex maliyeti yaratır; fazlasını kesiyoruz.
MAX_LINE_LEN = 4096
# Bir dosyadan (gz ise açılmış halde) okunacak en fazla bayt
DEFAULT_MAX_BYTES = 200 * 1024 * 1024


class ScanLimitError(Exception):
    """Dosya boyut sınırı aşıldı (tarama eksik kalmasın diye hata olarak bildirilir)."""


# Örnek satır:
# Oct 21 01:00:01 srv01 sshd[1001]: Failed password for root from 1.2.3.4 port 22 ssh2
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s+"
    r"(?P<msg>.*)$"
)

# IPv4 + IPv6 için basit karakter kümesi (gerçek doğrulamayı kasıtlı yapmıyoruz).
_IP = r"[0-9A-Fa-f:.]+"

# (process, event_type, regex). Sıra önemli: ilk eşleşen kazanır.
PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # Başarısız SSH girişi (geçersiz kullanıcı için de aynı satır biçimi)
    ("sshd", "ssh_failed", re.compile(
        rf"^Failed (?:password|publickey) for (?:invalid user )?"
        rf"(?P<user>\S+) from (?P<ip>{_IP}) port \d+")),
    # Başarılı SSH girişi
    ("sshd", "ssh_accepted", re.compile(
        rf"^Accepted \w+ for (?P<user>\S+) from (?P<ip>{_IP}) port \d+")),
    # Sistemde olmayan kullanıcı adıyla deneme (kullanıcı keşfi)
    ("sshd", "invalid_user", re.compile(
        rf"^Invalid user (?P<user>\S*) from (?P<ip>{_IP})")),
    # sudoers'da olmayan kullanıcının sudo denemesi
    ("sudo", "sudo_denied", re.compile(
        r"^(?P<user>\S+) : .*user NOT in sudoers")),
    # sudo parola hatası (PAM)
    ("sudo", "sudo_denied", re.compile(
        r"authentication failure;.*\buser=(?P<user>\S+)")),
    # Başarılı sudo komutu
    ("sudo", "sudo_command", re.compile(
        r"^(?P<user>\S+) : TTY=.*COMMAND=")),
]


def classify(process: str, message: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Mesajı sınıflandırır -> (event_type, user, source_ip). Eşleşme yoksa hepsi None."""
    for proc, event_type, pattern in PATTERNS:
        if proc != process:
            continue
        m = pattern.search(message)
        if m:
            groups = m.groupdict()
            return event_type, groups.get("user"), groups.get("ip")
    return None, None, None


def read_lines(path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[str]:
    """Dosyayı (düz veya .gz) güvenli biçimde satır satır okur.

    * Tek satır MAX_LINE_LEN'den uzunsa kalanı atılır (bellek şişmesin).
    * Toplam okunan (açılmış) bayt max_bytes'ı aşarsa ScanLimitError fırlatır.
    """
    opener = gzip.open if str(path).endswith(".gz") else open
    total = 0
    with opener(path, "rb") as fh:
        while True:
            chunk = fh.readline(MAX_LINE_LEN + 1)   # En fazla MAX_LINE_LEN+1 bayt okur
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ScanLimitError(f"boyut sınırı aşıldı (> {max_bytes // (1024 * 1024)} MB)")
            if len(chunk) > MAX_LINE_LEN and not chunk.endswith(b"\n"):
                # Aşırı uzun satır: satır sonuna kadar olan kalanı oku ve çöpe at
                while True:
                    rest = fh.readline(MAX_LINE_LEN + 1)
                    total += len(rest)
                    if total > max_bytes:
                        raise ScanLimitError(f"boyut sınırı aşıldı (> {max_bytes // (1024 * 1024)} MB)")
                    if not rest or rest.endswith(b"\n"):
                        break
            yield chunk.decode("utf-8", errors="replace")


def parse_lines(lines: Iterable[str], year: Optional[int] = None, source: str = "") -> list[Event]:
    """Satır akışını zamana göre sıralı Event listesine çevirir.

    year: Syslog satırlarında yıl bulunmaz; verilmezse bu yıl varsayılır.
    (Not: Aralık->Ocak yıl geçişi bu sürümde ele alınmıyor.)
    """
    year = year or datetime.now().year
    events: list[Event] = []

    for line_no, line in enumerate(lines, start=1):
        line = line.rstrip("\r\n")[:MAX_LINE_LEN]
        m = SYSLOG_RE.match(line)
        if not m:
            continue  # Syslog biçiminde olmayan satırı sessizce atla

        month = MONTHS.get(m["mon"])
        if month is None:
            continue
        hh, mm, ss = (int(x) for x in m["time"].split(":"))
        try:
            ts = datetime(year, month, int(m["day"]), hh, mm, ss)
        except ValueError:
            continue  # Geçersiz tarih (örn. 31 Nisan, 29 Şubat) -> atla

        event_type, user, ip = classify(m["proc"], m["msg"])
        events.append(Event(
            line_no=line_no, ts=ts, host=m["host"], process=m["proc"],
            message=m["msg"], raw=line, event_type=event_type,
            user=user, source_ip=ip, source=source,
        ))

    # Eşik/pencere hesabı sıralı veri ister.
    events.sort(key=lambda e: (e.ts, e.line_no))
    return events


def parse_auth_log(path: str | Path, year: Optional[int] = None) -> list[Event]:
    """Tek bir auth.log dosyasını okuyup ayrıştırır (kısayol)."""
    return parse_lines(read_lines(path), year=year, source=Path(path).as_posix())


# Parser kayıt defteri: yeni log biçimi eklemek = fonksiyon yazıp kaydetmek.
# Fonksiyon imzası: fn(lines, year, source) -> list[Event]
PARSERS: dict[str, Callable[..., list[Event]]] = {"auth": parse_lines}


def register_parser(name: str, fn: Callable[..., list[Event]]) -> None:
    """Dışarıdan yeni bir log ayrıştırıcısı ekler (eklenti noktası)."""
    PARSERS[name] = fn
