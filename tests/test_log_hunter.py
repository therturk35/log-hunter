"""log-hunter testleri. Çalıştırma: pytest -q"""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from log_hunter.engine import evaluate
from log_hunter.models import Alert, Event
from log_hunter.parsers import parse_auth_log
from log_hunter.report import to_html
from log_hunter.rules import RuleError, load_rules

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "auth.log"
RULES = ROOT / "log_hunter" / "builtin_rules"
T0 = datetime(2026, 10, 21, 1, 0, 0)


def make_event(sec: int, etype="ssh_failed", ip="203.0.113.1", user="x") -> Event:
    """Test için sahte olay üretir (T0'dan 'sec' saniye sonra)."""
    return Event(line_no=sec, ts=T0 + timedelta(seconds=sec), host="h", process="sshd",
                 message="m", raw=f"raw {sec}", event_type=etype, user=user, source_ip=ip)


def write_rule(tmp_path: Path, body: str) -> Path:
    (tmp_path / "r.yml").write_text(body, encoding="utf-8")
    return tmp_path


VALID_RULE = """
id: T-1
title: test
severity: high
mitre: T1110
type: threshold
where: {event_type: ssh_failed}
group_by: source_ip
threshold: 3
window_seconds: 10
"""


# ---------- Ayrıştırıcı ----------
def test_parser_reads_sample_and_classifies():
    events = parse_auth_log(SAMPLE, year=2026)
    types = {e.event_type for e in events}
    assert {"ssh_failed", "ssh_accepted", "invalid_user", "sudo_denied", "sudo_command"} <= types
    # Sıralı olmalı
    assert events == sorted(events, key=lambda e: (e.ts, e.line_no))


def test_parser_skips_garbage(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("çöp satır\nFoo 99 99:99:99 h p: x\n", encoding="utf-8")
    assert parse_auth_log(log, year=2026) == []


# ---------- Motor ----------
def test_threshold_fires_only_at_threshold(tmp_path):
    rules = load_rules(write_rule(tmp_path, VALID_RULE))
    assert len(evaluate([make_event(0), make_event(1)], rules)) == 0          # eşik altı
    assert len(evaluate([make_event(0), make_event(1), make_event(2)], rules)) == 1


def test_threshold_respects_window(tmp_path):
    rules = load_rules(write_rule(tmp_path, VALID_RULE))
    spread = [make_event(0), make_event(20), make_event(40)]                   # pencere dışı
    assert evaluate(spread, rules) == []


def test_threshold_groups_by_ip(tmp_path):
    rules = load_rules(write_rule(tmp_path, VALID_RULE))
    mixed = [make_event(0, ip="1.1.1.1"), make_event(1, ip="2.2.2.2"), make_event(2, ip="1.1.1.1")]
    assert evaluate(mixed, rules) == []                                         # IP'ler ayrı sayılır


def test_followed_by_requires_follower(tmp_path):
    body = VALID_RULE + "followed_by: {event_type: ssh_accepted}\n"
    rules = load_rules(write_rule(tmp_path, body))
    burst = [make_event(0), make_event(1), make_event(2)]
    assert evaluate(burst, rules) == []                                         # başarılı giriş yok
    with_success = burst + [make_event(5, etype="ssh_accepted")]
    assert len(evaluate(with_success, rules)) == 1
    other_ip = burst + [make_event(5, etype="ssh_accepted", ip="9.9.9.9")]
    assert evaluate(other_ip, rules) == []                                      # farklı IP sayılmaz


def test_sample_end_to_end():
    alerts = evaluate(parse_auth_log(SAMPLE, year=2026), load_rules(RULES))
    ids = [a.rule_id for a in alerts]
    assert sorted(ids) == ["LH-001", "LH-002", "LH-003", "LH-004", "LH-005"]
    assert alerts[0].severity == "critical"                                     # en önemli başta


# ---------- Kural doğrulama ----------
@pytest.mark.parametrize("old,new", [
    ("severity: high", "severity: urgent"),
    ("mitre: T1110", "mitre: <script>"),
    ("threshold: 3", "threshold: true"),
    ("group_by: source_ip", "group_by: raw"),
    ("where: {event_type: ssh_failed}", "where: {password: x}"),
])
def test_bad_rules_rejected(tmp_path, old, new):
    with pytest.raises(RuleError):
        load_rules(write_rule(tmp_path, VALID_RULE.replace(old, new)))


def test_yaml_code_execution_is_blocked(tmp_path):
    # safe_load, !!python/object gibi etiketleri reddetmeli (kod çalıştırma koruması)
    evil = "!!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(RuleError):
        load_rules(write_rule(tmp_path, evil))


# ---------- Rapor ----------
def test_html_report_escapes_log_content():
    evil = make_event(0)
    evil.raw = "<script>alert(1)</script>"
    alert = Alert("T-1", "<b>x</b>", "high", "T1110", "", "<img src=x>", 1, T0, T0, [evil])
    out = to_html([alert], source="<svg onload=x>")
    assert "<script>alert(1)" not in out
    assert "<img src=x>" not in out
    assert "&lt;script&gt;" in out
