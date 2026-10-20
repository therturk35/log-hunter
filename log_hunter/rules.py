"""YAML kural dosyalarını yükler ve doğrular.

Kural tipleri:
  match     -> koşula uyan HER olay için uyarı üretir.
  threshold -> aynı 'group_by' değerine sahip olaylardan, 'window_seconds'
               içinde en az 'threshold' kadar varsa uyarı üretir.
               İsteğe bağlı 'followed_by': eşik aşıldıktan sonra aynı anahtar
               için bu koşula uyan bir olay da gelirse uyarı verir
               (örn. brute-force + ardından başarılı giriş).

Güvenlik notları:
  * yaml.safe_load kullanılır; yaml.load KULLANILMAZ (rastgele Python nesnesi
    oluşturup kod çalıştırabilir).
  * Her alan beyaz listeyle doğrulanır; kural dosyasından gelen değerler
    asla eval/exec edilmez.
  * Kural dosyalarına güvenilen kaynaktan (kendi repon) sahip olun: karmaşık
    regex'ler yavaşlığa (ReDoS) yol açabilir.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

SEVERITIES = ("low", "medium", "high", "critical")
RULE_TYPES = ("match", "threshold")
# Kuralların bakabileceği Event alanları (beyaz liste)
EVENT_FIELDS = ("event_type", "user", "source_ip", "host", "process")
# Gruplama için izin verilen alanlar
GROUP_FIELDS = ("source_ip", "user", "host", "process")

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")  # T1110 veya T1110.001


# Pakete dahil gelen varsayılan kurallar
DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "builtin_rules"


class RuleError(ValueError):
    """Geçersiz / okunamayan kural."""


@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: str
    mitre: str
    type: str
    where: dict[str, str]
    where_regex: dict[str, re.Pattern[str]] = field(default_factory=dict)
    group_by: Optional[str] = None
    threshold: int = 0
    window_seconds: int = 0
    followed_by: Optional[dict[str, str]] = None

    def matches(self, event) -> bool:
        """Olay kuralın ana koşuluna uyuyor mu?"""
        for key, expected in self.where.items():
            if getattr(event, key) != expected:
                return False
        for key, pattern in self.where_regex.items():
            if not pattern.search(getattr(event, key) or ""):
                return False
        return True

    def follow_matches(self, event) -> bool:
        """Olay 'followed_by' koşuluna uyuyor mu? (tanımlı değilse False)"""
        if not self.followed_by:
            return False
        return all(getattr(event, k) == v for k, v in self.followed_by.items())


def _need(data: dict, key: str, src: str) -> Any:
    if key not in data:
        raise RuleError(f"{src}: zorunlu alan eksik: '{key}'")
    return data[key]


def _pos_int(value: Any, name: str, src: str) -> int:
    # bool, int'in alt sınıfıdır; 'true' değerini sayı sanmasın diye ayrıca eliyoruz.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RuleError(f"{src}: '{name}' pozitif bir tam sayı olmalı")
    return value


def _check_where(where: Any, name: str, src: str) -> dict[str, str]:
    if not isinstance(where, dict) or not where:
        raise RuleError(f"{src}: '{name}' boş olmayan bir sözlük olmalı")
    for key, value in where.items():
        if key not in EVENT_FIELDS:
            raise RuleError(f"{src}: '{name}' içinde geçersiz alan: '{key}'")
        if not isinstance(value, str):
            raise RuleError(f"{src}: '{name}.{key}' metin olmalı")
    return where


def _build_rule(data: Any, src: str) -> Rule:
    if not isinstance(data, dict):
        raise RuleError(f"{src}: kural bir YAML sözlüğü olmalı")

    rule_id = _need(data, "id", src)
    if not isinstance(rule_id, str) or not ID_RE.match(rule_id):
        raise RuleError(f"{src}: geçersiz 'id'")

    severity = _need(data, "severity", src)
    if severity not in SEVERITIES:
        raise RuleError(f"{src}: 'severity' şunlardan biri olmalı: {SEVERITIES}")

    mitre = _need(data, "mitre", src)
    if not isinstance(mitre, str) or not MITRE_RE.match(mitre):
        raise RuleError(f"{src}: 'mitre' biçimi geçersiz (örn. T1110 veya T1110.001)")

    rule_type = _need(data, "type", src)
    if rule_type not in RULE_TYPES:
        raise RuleError(f"{src}: 'type' şunlardan biri olmalı: {RULE_TYPES}")

    title = _need(data, "title", src)
    if not isinstance(title, str) or not title.strip():
        raise RuleError(f"{src}: 'title' boş olamaz")

    where = _check_where(_need(data, "where", src), "where", src)

    # İsteğe bağlı: mesaj/alan üzerinde regex koşulu
    where_regex: dict[str, re.Pattern[str]] = {}
    raw_regex = data.get("where_regex") or {}
    if not isinstance(raw_regex, dict):
        raise RuleError(f"{src}: 'where_regex' sözlük olmalı")
    for key, pattern in raw_regex.items():
        if key not in EVENT_FIELDS + ("message",):
            raise RuleError(f"{src}: 'where_regex' içinde geçersiz alan: '{key}'")
        try:
            where_regex[key] = re.compile(str(pattern))
        except re.error as exc:
            raise RuleError(f"{src}: geçersiz regex ({key}): {exc}") from exc

    rule = Rule(
        id=rule_id, title=title.strip(),
        description=str(data.get("description", "")).strip(),
        severity=severity, mitre=mitre, type=rule_type,
        where=where, where_regex=where_regex,
    )

    if rule_type == "threshold":
        group_by = _need(data, "group_by", src)
        if group_by not in GROUP_FIELDS:
            raise RuleError(f"{src}: 'group_by' şunlardan biri olmalı: {GROUP_FIELDS}")
        rule.group_by = group_by
        rule.threshold = _pos_int(_need(data, "threshold", src), "threshold", src)
        rule.window_seconds = _pos_int(_need(data, "window_seconds", src), "window_seconds", src)
        if "followed_by" in data:
            rule.followed_by = _check_where(data["followed_by"], "followed_by", src)

    return rule


def load_rules(directory: str | Path | None = None) -> list[Rule]:
    """Klasördeki tüm *.yml / *.yaml kurallarını yükler ve doğrular.

    directory verilmezse pakete dahil varsayılan kurallar kullanılır.
    """
    folder = Path(directory) if directory else DEFAULT_RULES_DIR
    if not folder.is_dir():
        raise RuleError(f"Kural klasörü bulunamadı: {folder}")

    files = sorted(list(folder.glob("*.yml")) + list(folder.glob("*.yaml")))
    if not files:
        raise RuleError(f"Klasörde kural dosyası yok: {folder}")

    rules: list[Rule] = []
    seen: set[str] = set()
    for path in files:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RuleError(f"{path.name}: YAML hatası: {exc}") from exc
        rule = _build_rule(data, path.name)
        if rule.id in seen:
            raise RuleError(f"{path.name}: tekrar eden kural id'si: {rule.id}")
        seen.add(rule.id)
        rules.append(rule)
    return rules
