"""Send real packets with a spoofed source address.

This is not a simulation: Scapy sets IP.src to the chosen address and transmits
the frame. Replies go to the spoofed host, not back to this machine.
Requires Administrator/root and Npcap (Windows) or raw sockets (Linux).
"""

from __future__ import annotations

import random
from typing import Any

from scapy.all import ICMP, IP, TCP, UDP, Raw, conf, send  # type: ignore

from netlab.base import BaseModule, ModuleParam

MAX_PACKETS = 2000


class IpSpoof(BaseModule):
    name = "ip_spoof"
    description = "Transmit packets whose source IP is not ours"
    category = "l3_l4"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(name="source", type="ip", label="Spoofed source IP", required=True),
            ModuleParam(name="target", type="ip", label="Destination IP", required=True),
            ModuleParam(
                name="protocol",
                type="str",
                label="Protocol",
                required=False,
                default="tcp",
                description="tcp | udp | icmp",
            ),
            ModuleParam(
                name="port",
                type="int",
                label="Destination port",
                required=False,
                default=80,
                description="Used for tcp and udp",
            ),
            ModuleParam(
                name="interface",
                type="interface",
                label="Interface",
                required=False,
                default=None,
            ),
            ModuleParam(
                name="count",
                type="int",
                label="Packets",
                required=False,
                default=20,
                description=f"Hard cap {MAX_PACKETS}",
            ),
            ModuleParam(
                name="rate_limit_pps",
                type="int",
                label="Rate limit (pps)",
                required=False,
                default=20,
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        source = params["source"]
        target = params["target"]
        proto = str(params.get("protocol", "tcp")).lower()
        port = int(params.get("port", 80))
        iface = params.get("interface") or None
        count = min(int(params.get("count", 20)), MAX_PACKETS)
        if proto not in ("tcp", "udp", "icmp"):
            raise ValueError("protocol must be tcp, udp or icmp")
        if iface:
            conf.iface = iface
        conf.verb = 0

        print(f"[ip_spoof] {count} {proto} packets {source} -> {target}")
        for i in range(count):
            if self.should_stop():
                print("[ip_spoof] Stopped")
                break
            rate_limiter.wait()
            ip = IP(src=source, dst=target)
            if proto == "tcp":
                pkt = ip / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            elif proto == "udp":
                pkt = ip / UDP(sport=random.randint(1024, 65535), dport=port) / Raw(b"LAB")
            else:
                pkt = ip / ICMP()
            send(pkt, verbose=0)
            logger.add_packets(1, len(bytes(pkt)))
            if (i + 1) % 50 == 0:
                print(f"  sent {i + 1}/{count}")
        print("── IP spoof finished ──")
        print("  The destination will answer the spoofed source, not this host.")
