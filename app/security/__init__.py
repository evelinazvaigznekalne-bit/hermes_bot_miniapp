"""Secret-shape detection: warn, never store."""
from .secret_scan import SecretFinding, mask, scan, warning_text

__all__ = ["SecretFinding", "scan", "warning_text", "mask"]
