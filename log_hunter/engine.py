"""Kural motoru: Event listesi + Rule listesi -> Alert listesi."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterator, Optional

from .models import Alert, Event
from .rules import Rule

# Uyarıları önem sırasına dizmek için
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Raporun şişmemesi için bir uyarıya eklenecek en fazla kanıt satırı
MAX_EVIDENCE = 20


def _bursts(events: list[Event], threshold: int, window_seconds: int) -> Iterator[list[Event]]:
    """Kayan pencere: 'window_seconds' içinde >= 'threshold' olay biriktiren grupları verir.

    events zamana göre SIRALI olmalıdır. Bir grup üretilince sayaç sıfırlanır
    (start = end + 1); böylece aynı olaylar iki kez uyarı üretmez.
    """
    window = timedelta(seconds=window_seconds)
    start = 0
    for end in range(len(events)):
        # Pencere dışında kalan eski olayları baştan at
        while events[end].ts - events[start].ts > window:
            start += 1
        if end - start + 1 >= threshold:
            yield events[start:end + 1]
            start = end + 1


def _find_follower(candidates: list[Event], after: datetime, window_seconds: int) -> Optional[Event]:
    """'after' anından sonraki 'window_seconds' içinde gelen ilk adayı döndürür."""
    limit = after + timedelta(seconds=window_seconds)
    for event in candidates:  # candidates zaman sıralı
        if after <= event.ts <= limit:
            return event
    return None


def _make_alert(rule: Rule, key: str, evidence: list[Event], count: Optional[int] = None) -> Alert:
    return Alert(
        rule_id=rule.id, title=rule.title, severity=rule.severity,
        mitre=rule.mitre, description=rule.description, key=key,
        count=count if count is not None else len(evidence),
        first_seen=evidence[0].ts, last_seen=evidence[-1].ts,
        evidence=evidence[:MAX_EVIDENCE],
    )


def evaluate(events: list[Event], rules: list[Rule]) -> list[Alert]:
    """Tüm kuralları olaylara uygular; önem + zamana göre sıralı uyarı listesi döndürür."""
    alerts: list[Alert] = []

    for rule in rules:
        hits = [e for e in events if rule.matches(e)]

        if rule.type == "match":
            # Tek olay yeterli: her eşleşme ayrı uyarı
            for e in hits:
                alerts.append(_make_alert(rule, e.source_ip or e.user or "-", [e]))
            continue

        # --- threshold kuralı ---
        # 1) Olayları gruplama anahtarına (örn. kaynak IP) göre ayır
        groups: dict[str, list[Event]] = defaultdict(list)
        for e in hits:
            key = getattr(e, rule.group_by)
            if key is not None:
                groups[key].append(e)

        # 2) 'followed_by' varsa takip eden olayları da aynı anahtarla grupla
        followers: dict[str, list[Event]] = defaultdict(list)
        if rule.followed_by:
            for e in events:
                if rule.follow_matches(e):
                    key = getattr(e, rule.group_by)
                    if key is not None:
                        followers[key].append(e)

        # 3) Her grupta eşiği aşan patlamaları (burst) bul
        for key, group_events in groups.items():
            for burst in _bursts(group_events, rule.threshold, rule.window_seconds):
                evidence = list(burst)
                if rule.followed_by:
                    follower = _find_follower(
                        followers.get(key, []), burst[-1].ts, rule.window_seconds)
                    if follower is None:
                        continue  # Takip eden olay yok -> bu kural için uyarı yok
                    evidence.append(follower)
                alerts.append(_make_alert(rule, key, evidence, count=len(burst)))

    alerts.sort(key=lambda a: (-SEVERITY_RANK[a.severity], a.first_seen))
    return alerts
