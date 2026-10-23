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
    save_logs: bool = True
    # Global defaults can be extended later


def default_interface() -> str:
    """Pick the interface used for the default IPv4 route, skipping loopback and bridges."""
    import socket

    import psutil

    try:
        from scapy.config import conf as scapy_conf

        iface, _gw, _ip = scapy_conf.route.route("8.8.8.8")
        if iface and str(iface) not in ("lo", "lo0"):
            return str(iface)
    except Exception:
        pass

    skip_prefix = ("lo", "docker", "br-", "veth", "virbr", "vmnet", "tun", "tap", "tailscale")
    for name, st in psutil.net_if_stats().items():
        if not st.isup or name.startswith(skip_prefix):
            continue
        for addr in psutil.net_if_addrs().get(name, []):
            if addr.family == socket.AF_INET and not str(addr.address).startswith("127."):
                return name
    raise RuntimeError("No active network interface found")


def load_config(path: str | Path = "configs/default.yaml") -> NetLabConfig:
    path = Path(path)
    if not path.exists():
        return NetLabConfig()
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return NetLabConfig(**data)


def load_gui_settings(path: str | Path = "configs/gui.yaml") -> dict[str, Any]:
    path = Path(path)
    defaults: dict[str, Any] = {
        "language": "ru",
        "theme": "dark",
        "save_logs": True,
        "last_module": None,
        "module_params": {},
        "custom_themes": {},
        "window_width": 1120,
        "window_height": 740,
    }
    if not path.exists():
        return dict(defaults)
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    out = dict(defaults)
    out["language"] = data.get("language", "ru")
    out["theme"] = data.get("theme", "dark")
    out["save_logs"] = bool(data.get("save_logs", True))
    out["last_module"] = data.get("last_module")
    out["module_params"] = data.get("module_params") or {}
    out["custom_themes"] = data.get("custom_themes") or {}
    out["window_width"] = int(data.get("window_width", 1120))
    out["window_height"] = int(data.get("window_height", 740))
    return out


def save_gui_settings(settings: dict[str, Any], path: str | Path = "configs/gui.yaml") -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "language": settings.get("language", "ru"),
        "theme": settings.get("theme", "dark"),
        "save_logs": bool(settings.get("save_logs", True)),
        "last_module": settings.get("last_module"),
        "module_params": settings.get("module_params") or {},
        "custom_themes": settings.get("custom_themes") or {},
        "window_width": int(settings.get("window_width", 1120)),
        "window_height": int(settings.get("window_height", 740)),
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(payload, f, default_flow_style=False, allow_unicode=True)


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
        self.config.save_logs = load_gui_settings().get("save_logs", self.config.save_logs)
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
        on_start: Any = None,
    ) -> AttackLogger:
        if name not in self.modules:
            raise KeyError(f"Unknown module: {name}")

        cls = self.modules[name]
        instance = cls()
        validated = instance.validate_params(params)
        names = {p.name for p in cls.parameters()}
        if "interface" in names and not validated.get("interface"):
            validated["interface"] = default_interface()
        if validated.get("interface"):
            print(f"  Interface        {validated['interface']}")

        # Rate limit: explicit > module default > global config
        pps = rate_limit_pps
        if pps is None:
            pps = validated.get("rate_limit_pps", self.config.default_rate_limit_pps)
        limiter = RateLimiter(pps)

        if on_start is not None:
            on_start(instance)

        logger = AttackLogger(
            module_name=name,
            parameters=validated,
            log_dir=self.config.log_dir,
            enabled=self.config.save_logs,
        )
        logger.start()

        try:
            instance.run(validated, logger, limiter)
            logger.stop("stopped" if instance.should_stop() else "completed")
        except KeyboardInterrupt:
            logger.stop("stopped")
        except Exception as exc:  # noqa: BLE001
            logger.error(str(exc))
            raise

        return logger
