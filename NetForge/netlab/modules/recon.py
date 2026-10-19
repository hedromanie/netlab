"""Reconnaissance modules (host discovery + port scan)."""

from __future__ import annotations

import ipaddress
import random
from typing import Any

from scapy.all import (  # type: ignore
    ARP,
    Ether,
    ICMP,
    IP,
    TCP,
    sr,
    srp,
    conf,
)

from netlab.base import BaseModule, ModuleParam


def _parse_ports(ports_str: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or mixed into sorted unique list."""
    result: set[int] = set()
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            # safety cap
            if end - start > 10000:
                raise ValueError("Port range too large (max 10000 ports)")
            result.update(range(start, end + 1))
        else:
            result.add(int(part))
    return sorted(p for p in result if 1 <= p <= 65535)


class HostDiscovery(BaseModule):
    name = "host_discovery"
    description = "Discover live hosts in a subnet (ARP + ICMP)"
    category = "recon"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(
                name="target",
                type="str",
                label="Target subnet / IP",
                required=True,
                description="e.g. 192.168.1.0/24 or 192.168.1.10",
            ),
            ModuleParam(
                name="interface",
                type="interface",
                label="Network interface",
                required=False,
                default=None,
                description="Leave empty for auto-detect",
            ),
            ModuleParam(
                name="timeout",
                type="float",
                label="Timeout (seconds)",
                required=False,
                default=2.0,
            ),
            ModuleParam(
                name="method",
                type="str",
                label="Method",
                required=False,
                default="arp",
                description="arp | icmp | both",
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        target = params["target"]
        iface = params.get("interface")
        timeout = float(params.get("timeout", 2.0))
        method = str(params.get("method", "arp")).lower()

        if iface:
            conf.iface = iface

        live_hosts: list[dict[str, str]] = []

        # --- ARP discovery (best for local subnet) ---
        if method in ("arp", "both"):
            try:
                network = ipaddress.ip_network(target, strict=False)
                arp = ARP(pdst=str(network))
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp

                answered, _ = srp(packet, timeout=timeout, verbose=0, iface=iface)

                for _, rcv in answered:
                    host = {"ip": rcv.psrc, "mac": rcv.hwsrc}
                    live_hosts.append(host)
                    logger.add_packets(1, len(bytes(rcv)))

            except ValueError:
                # single IP fallback
                answered, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
                    timeout=timeout,
                    verbose=0,
                    iface=iface,
                )
                for _, rcv in answered:
                    live_hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
                    logger.add_packets(1, len(bytes(rcv)))

        # --- ICMP discovery ---
        if method in ("icmp", "both"):
            try:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
            except ValueError:
                hosts = [ipaddress.ip_address(target)]

            # limit to reasonable size for lab
            if len(hosts) > 1024:
                hosts = hosts[:1024]

            for host in hosts:
                rate_limiter.wait()
                pkt = IP(dst=str(host)) / ICMP()
                ans, _ = sr(pkt, timeout=timeout, verbose=0, iface=iface)
                if ans:
                    live_hosts.append({"ip": str(host), "mac": ""})
                    logger.add_packets(1, len(bytes(pkt)))

        # deduplicate by IP
        seen = set()
        unique = []
        for h in live_hosts:
            if h["ip"] not in seen:
                seen.add(h["ip"])
                unique.append(h)

        print(f"[host_discovery] Found {len(unique)} live host(s):")
        for h in unique:
            mac_part = f"  ({h['mac']})" if h.get("mac") else ""
            print(f"  • {h['ip']}{mac_part}")


class PortScan(BaseModule):
    name = "port_scan"
    description = "TCP SYN port scanner"
    category = "recon"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(
                name="target",
                type="ip",
                label="Target IP",
                required=True,
            ),
            ModuleParam(
                name="ports",
                type="str",
                label="Ports",
                required=False,
                default="21,22,23,25,53,80,110,135,139,443,445,3389,8080",
                description="e.g. 22,80,443 or 1-1024",
            ),
            ModuleParam(
                name="interface",
                type="interface",
                label="Network interface",
                required=False,
                default=None,
            ),
            ModuleParam(
                name="timeout",
                type="float",
                label="Timeout per port (sec)",
                required=False,
                default=1.0,
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
        target = params["target"]
        ports_str = params.get("ports", "1-1024")
        iface = params.get("interface")
        timeout = float(params.get("timeout", 1.0))

        if iface:
            conf.iface = iface

        ports = _parse_ports(ports_str)
        if not ports:
            raise ValueError("No valid ports specified")

        open_ports: list[int] = []

        print(f"[port_scan] Scanning {target} — {len(ports)} port(s)...")

        for port in ports:
            rate_limiter.wait()

            # random source port
            sport = random.randint(1024, 65535)
            pkt = IP(dst=target) / TCP(sport=sport, dport=port, flags="S")

            ans, _ = sr(pkt, timeout=timeout, verbose=0, iface=iface)
            logger.add_packets(1, len(bytes(pkt)))

            if ans:
                resp = ans[0][1]
                if resp.haslayer(TCP) and resp[TCP].flags & 0x12:  # SYN-ACK
                    open_ports.append(port)
                    # send RST to be polite
                    rst = IP(dst=target) / TCP(sport=sport, dport=port, flags="R")
                    # no need to wait for answer
                    from scapy.all import send
                    send(rst, verbose=0, iface=iface)
                    logger.add_packets(1, len(bytes(rst)))

        print(f"[port_scan] Open ports on {target}:")
        if open_ports:
            for p in open_ports:
                print(f"  • {p}/tcp open")
        else:
            print("  (none found)")
