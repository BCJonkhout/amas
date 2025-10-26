"""Core package for the Automated Multi-Agent Security (AMAS) system."""

from importlib import import_module
import sys
from types import ModuleType
from typing import Tuple

_SUBMODULES: Tuple[str, ...] = ("agents", "documentation", "mcp", "security_data", "tooling", "workflow")
__all__ = list(_SUBMODULES)

_current_module = sys.modules[__name__]
for _name in _SUBMODULES:
    submodule = import_module(f"{__name__}.{_name}")
    setattr(_current_module, _name, submodule)

# Provide `amas` as an alias so callers can `import amas` or `from amas import workflow`.
sys.modules.setdefault("amas", _current_module)
for _name in _SUBMODULES:
    module: ModuleType = sys.modules[f"{__name__}.{_name}"]
    sys.modules.setdefault(f"amas.{_name}", module)
