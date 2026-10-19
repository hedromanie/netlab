"""Core engine: config, privileges, rate limiter, attack runner."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from netlab.base import BaseModule, discover_modules
from netlab.logger import AttackLogger


# ---------------------------------------------------------------------------
# Privileges
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    """Return True if the current process has administrator / root rights."""
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    else:
        return os.geteuid() == 0


def require_admin() -> None:
    if not is_admin():
        sys.stderr.write(
            "[!] This tool requires Administrator (Windows) or root (Linux) privileges.\n"
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Simple token-bucket style rate limiter (packets per second)."""

    def __init__(self, pps: float = 0):
        """
        pps = 0  → unlimited
        pps > 0  → hard limit
        """
        self.pps = max(0.0, pps)
        self._last = 0.0
        self._interval = 1.0 / self.pps if self.pps > 0 else 0.0

    def wait(self) -> None:
        if self.pps <= 0:
            return
        import time
        now = time.perf_counter()
        elapsed = now - self._last
        if elapsed < self._interval:
            time.sleep(self._interval - elapsed)
        self._last = time.perf_counter()

    def set_rate(self, pps: float) -> None:
        self.pps = max(0.0, pps)
        self._interval = 1.0 / self.pps if self.pps > 0 else 0.0


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class NetLabConfig(BaseModel):
    interface: str | None = None
    log_dir: str = "logs"
    default_rate_limit_pps: int = 500
    # Global defaults can be extended later


def load_config(path: str | Path = "configs/default.yaml") -> NetLabConfig:
    path = Path(path)
    if not path.exists():
        return NetLabConfig()
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return NetLabConfig(**data)


def save_config(cfg: NetLabConfig, path: str | Path = "configs/default.yaml") -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg.model_dump(), f, default_flow_style=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class Engine:
    """Discovers modules and runs them with logging + rate limiting."""

    def __init__(self, config: NetLabConfig | None = None):
        self.config = config or load_config()
        self.modules: dict[str, type[BaseModule]] = discover_modules()

    def list_modules(self) -> list[dict[str, Any]]:
        result = []
        for name, cls in sorted(self.modules.items()):
            result.append(
                {
                    "name": name,
                    "description": cls.description,
                    "category": cls.category,
                    "parameters": [p.model_dump() for p in cls.parameters()],
                }
            )
        return result

    def run_module(
        self,
        name: str,
        params: dict[str, Any],
        rate_limit_pps: float | None = None,
    ) -> AttackLogger:
        if name not in self.modules:
            raise KeyError(f"Unknown module: {name}")

        cls = self.modules[name]
        instance = cls()
        validated = instance.validate_params(params)

        # Rate limit: explicit > module default > global config
        pps = rate_limit_pps
        if pps is None:
            pps = validated.get("rate_limit_pps", self.config.default_rate_limit_pps)
        limiter = RateLimiter(pps)

        logger = AttackLogger(
            module_name=name,
            parameters=validated,
            log_dir=self.config.log_dir,
        )
        logger.start()

        try:
            instance.run(validated, logger, limiter)
            logger.stop("completed")
        except KeyboardInterrupt:
            logger.stop("stopped")
        except Exception as exc:  # noqa: BLE001
            logger.error(str(exc))
            raise

        return logger
