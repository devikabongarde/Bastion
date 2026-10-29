"""BaselineGuard Adapters: reading, normalization, and orchestration."""

from baselineguard_adapters.normalize import fact
from baselineguard_adapters.orchestrate import normalize_outputs

__all__ = ["fact", "normalize_outputs"]

