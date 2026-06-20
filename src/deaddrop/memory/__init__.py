"""Memory forensics package."""

from deaddrop.memory.analyzer import MemoryAnalyzer as MemoryAnalyzer
from deaddrop.memory.volatility import VolatilityWrapper as VolatilityWrapper

__all__ = ["MemoryAnalyzer", "VolatilityWrapper"]
