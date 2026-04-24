"""Memory forensics package."""

from deaddrop.memory.volatility import VolatilityWrapper as VolatilityWrapper
from deaddrop.memory.analyzer import MemoryAnalyzer as MemoryAnalyzer

__all__ = ["VolatilityWrapper", "MemoryAnalyzer"]