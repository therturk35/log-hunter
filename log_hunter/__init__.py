"""log-hunter: hafif, kural tabanlı (Sigma tarzı YAML) log tarama motoru."""

__version__ = "0.2.0"

# Herkese açık (public) API
from .rules import Rule, RuleError, load_rules  # noqa: E402
from .scanner import ScanResult, Scanner  # noqa: E402

__all__ = ["Scanner", "ScanResult", "Rule", "RuleError", "load_rules", "__version__"]
