"""Ortak veri modelleri.

Event : log dosyasından ayrıştırılmış tek bir satır (normalize edilmiş hali).
Alert : bir kuralın ürettiği tespit (kanıt olarak ilgili Event'leri taşır).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class Event:
    line_no: int                      # Dosyadaki satır numarası (kanıt takibi için)
    ts: datetime                      # Olay zamanı (syslog'ta saat dilimi yok -> naive)
    host: str                         # Logu üreten makine adı
    process: str                      # sshd, sudo vb.
    message: str                      # Logun mesaj kısmı
    raw: str                          # Ham satır (rapora kanıt olarak girer)
    event_type: Optional[str] = None  # ssh_failed, ssh_accepted, invalid_user, ...
    user: Optional[str] = None        # Olaydaki kullanıcı adı
    source_ip: Optional[str] = None   # Olaydaki kaynak IP
    source: str = ""                  # Olayın geldiği dosya (rapor/SARIF konumu için)


@dataclass(slots=True)
class Alert:
    rule_id: str
    title: str
    severity: str                     # low | medium | high | critical
    mitre: str                        # MITRE ATT&CK teknik kimliği, örn. T1110
    description: str
    key: str                          # Gruplama anahtarı (genelde saldırgan IP)
    count: int                        # Eşiği aşan olay sayısı
    first_seen: datetime
    last_seen: datetime
    evidence: list[Event] = field(default_factory=list)
