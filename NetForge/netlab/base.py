"""Base classes and plugin loader for attack modules."""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ModuleParam(BaseModel):
    """Description of a single module parameter (used by CLI and Web UI)."""

    name: str
    type: str = Field(
        ...,
        description="str | int | float | ip | mac | interface | bool",
    )
    label: str
    required: bool = True
    default: Any = None
    description: str = ""


class BaseModule(ABC):
    """Abstract base class for every attack module.

    Any module that inherits from this class and lives in netlab.modules
    is automatically discovered by the plugin loader.
    """

    name: str = "unnamed"
    description: str = ""
    category: str = "misc"  # recon | l2 | l3_l4

    @classmethod
    @abstractmethod
    def parameters(cls) -> list[ModuleParam]:
        """Return the list of parameters this module accepts."""
        ...

    @abstractmethod
    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        """Execute the attack.

        Parameters
        ----------
        params:
            Validated dictionary of user-supplied parameters.
        logger:
            Instance of AttackLogger (already started).
        rate_limiter:
            Shared RateLimiter instance.
        """
        ...

    def validate_params(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Basic validation + fill defaults. Override for complex logic."""
        result: dict[str, Any] = {}
        for p in self.parameters():
            if p.name in raw and raw[p.name] is not None:
                result[p.name] = raw[p.name]
            elif p.default is not None:
                result[p.name] = p.default
            elif p.required:
                raise ValueError(f"Missing required parameter: {p.name}")
        return result


def discover_modules() -> dict[str, type[BaseModule]]:
    """Scan netlab.modules package and return {name: class} mapping."""
    import netlab.modules as modules_pkg

    found: dict[str, type[BaseModule]] = {}
    package_path = Path(modules_pkg.__file__).parent

    for module_info in pkgutil.iter_modules([str(package_path)]):
        if module_info.name.startswith("_"):
            continue
        full_name = f"netlab.modules.{module_info.name}"
        try:
            mod = importlib.import_module(full_name)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Failed to import {full_name}: {exc}")
            continue

        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseModule)
                and obj is not BaseModule
                and getattr(obj, "name", None)
            ):
                found[obj.name] = obj

    return found
