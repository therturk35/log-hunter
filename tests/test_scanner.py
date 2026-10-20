"""Tarama motoru (Scanner), SARIF ve CLI testleri."""

import gzip
import json
import shutil
from pathlib import Path

from log_hunter import Scanner, load_rules
from log_hunter.cli import main
from log_hunter.report import to_sarif

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "auth.log"
RULES = load_rules()


def fail_line(sec: int, ip="203.0.113.9") -> str:
    return f"Oct 21 01:00:{sec:02d} srv sshd[1]: Failed password for root from {ip} port 22 ssh2\n"


def test_directory_scan_filters_and_recurses(tmp_path):
    (tmp_path / "sub").mkdir()
    shutil.copy(SAMPLE, tmp_path / "auth.log")
    shutil.copy(SAMPLE, tmp_path / "sub" / "auth.log.1")
    (tmp_path / "notes.txt").write_text("ilgisiz")
    result = Scanner(RULES, year=2026).scan([tmp_path])
    assert len(result.files) == 2          # notes.txt taranmaz, alt klasör taranır
    assert result.errors == []


def test_gzip_file_equals_plain(tmp_path):
    gz = tmp_path / "auth.log.1.gz"
    gz.write_bytes(gzip.compress(SAMPLE.read_bytes()))
    plain = Scanner(RULES, year=2026).scan([SAMPLE])
    packed = Scanner(RULES, year=2026).scan([gz])
    assert [a.rule_id for a in packed.alerts] == [a.rule_id for a in plain.alerts]


def test_symlinks_skipped_in_directory(tmp_path):
    shutil.copy(SAMPLE, tmp_path / "real.log")
    (tmp_path / "link.log").symlink_to(tmp_path / "real.log")
    result = Scanner(RULES, year=2026).scan([tmp_path])
    assert len(result.files) == 1
    assert any("sembolik" in s for s in result.skipped)


def test_size_limit_reports_error_not_clean(tmp_path):
    big = tmp_path / "big.log"
    big.write_bytes(b"x" * 2_000_000)
    result = Scanner(RULES, max_file_bytes=1_000_000).scan([big])
    assert result.errors and result.files == []


def test_gzip_bomb_is_stopped(tmp_path):
    bomb = tmp_path / "bomb.log.gz"
    bomb.write_bytes(gzip.compress(b"A" * 5_000_000))     # tek satır, 5 MB açılmış
    result = Scanner(RULES, max_file_bytes=1_000_000).scan([bomb])
    assert result.errors and result.alerts == []


def test_cross_file_correlation(tmp_path):
    # Brute-force'un 3 denemesi bir dosyada, 2'si öbüründe: birleşince eşiği (5) aşar
    (tmp_path / "a.log").write_text("".join(fail_line(s) for s in (0, 1, 2)))
    (tmp_path / "b.log").write_text("".join(fail_line(s) for s in (3, 4)))
    result = Scanner(RULES, year=2026).scan([tmp_path])
    assert "LH-001" in [a.rule_id for a in result.alerts]


def test_missing_path_is_error():
    result = Scanner(RULES).scan(["/yok/boyle/bir/yol"])
    assert result.errors and result.files == []


def test_sarif_structure():
    result = Scanner(RULES, year=2026).scan([SAMPLE])
    doc = json.loads(to_sarif(result.alerts))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and len(run["results"]) == len(result.alerts)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in {"error", "warning", "note"}
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].endswith("auth.log")
        assert isinstance(loc["region"]["startLine"], int)


def test_cli_min_severity_sarif_and_exit_code(tmp_path, capsys):
    out = tmp_path / "r.sarif"
    code = main([str(SAMPLE), "--year", "2026", "--min-severity", "high",
                 "--sarif", str(out), "--fail-on-alert"])
    assert code == 1
    assert len(json.loads(out.read_text())["runs"][0]["results"]) == 3   # LH-002, LH-001, LH-003


def test_cli_missing_path_exit_2(capsys):
    assert main(["/yok/boyle/bir/yol"]) == 2
