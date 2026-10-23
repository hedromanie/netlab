"""Unified reconnaissance: one module, one command, one flag per technique."""

from __future__ import annotations

import ipaddress
import random
import socket
from typing import Any

from scapy.all import (  # type: ignore
    ARP,
    Ether,
    ICMP,
    IP,
    TCP,
    UDP,
    sr,
    srp,
    conf,
)

from netlab.base import BaseModule, ModuleParam

MAX_PORT_SPAN = 10000
MAX_HOSTS = 64
MAX_ARP_HOSTS = 4096
PROBE_TIMEOUT = 1.0
DEFAULT_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,3389,8080"


def parse_ports(ports_str: str) -> list[int]:
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
            if end - start > MAX_PORT_SPAN:
                raise ValueError(f"Port range too large (max {MAX_PORT_SPAN} ports)")
            result.update(range(start, end + 1))
        else:
            result.add(int(part))
    return sorted(p for p in result if 1 <= p <= 65535)


def _parse_ip_range(spec: str) -> list[str] | None:
    """Parse 192.168.1.0-192.168.1.255 or 192.168.1.10-50 (same third octet)."""
    if "-" not in spec or "/" in spec:
        return None
    left, right = [p.strip() for p in spec.split("-", 1)]
    try:
        start = ipaddress.ip_address(left)
    except ValueError:
        return None
    try:
        end = ipaddress.ip_address(right)
    except ValueError:
        if right.isdigit() and isinstance(start, ipaddress.IPv4Address):
            parts = str(start).split(".")
            end = ipaddress.ip_address(".".join(parts[:3] + [right]))
        else:
            return None
    if int(end) < int(start):
        start, end = end, start
    count = int(end) - int(start) + 1
    if count > MAX_ARP_HOSTS:
        raise ValueError(f"Range too large (max {MAX_ARP_HOSTS} addresses)")
    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]


def iter_hosts(target: str, limit: int = MAX_HOSTS) -> list[str]:
    ranged = _parse_ip_range(target.strip())
    if ranged is not None:
        if len(ranged) > limit:
            print(f"[recon] host list capped at {limit}")
            return ranged[:limit]
        return ranged
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [str(ipaddress.ip_address(target))]
    if network.num_addresses == 1:
        return [str(network.network_address)]
    hosts = [str(h) for h in network.hosts()]
    if len(hosts) > limit:
        print(f"[recon] host list capped at {limit}")
        hosts = hosts[:limit]
    return hosts


def network_hosts(target: str) -> list[str]:
    """Addresses to ARP-probe.

    - 192.168.1.0/24           → full subnet (all addresses in the prefix)
    - 192.168.1.0-192.168.1.255 → explicit range
    - 192.168.1.10-50          → short range on same /24
    - 192.168.1.1              → whole last-octet span .1 .. .255 (Gotcha-style /24 lab scan)
    """
    target = target.strip()
    ranged = _parse_ip_range(target)
    if ranged is not None:
        return ranged
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 1:
            start_i = int(network.network_address)
            end_i = int(network.broadcast_address)
            count = end_i - start_i + 1
            if count > MAX_ARP_HOSTS:
                raise ValueError(
                    f"ARP scan: {count} addresses exceeds max {MAX_ARP_HOSTS}."
                )
            return [str(ipaddress.ip_address(i)) for i in range(start_i, end_i + 1)]
    except ValueError:
        pass

    # Single host → expand to x.x.x.1 .. x.x.x.255 (skip .0)
    ip = ipaddress.ip_address(target)
    if not isinstance(ip, ipaddress.IPv4Address):
        return [str(ip)]
    parts = str(ip).split(".")
    base = ".".join(parts[:3])
    hosts = [f"{base}.{i}" for i in range(1, 256)]
    return hosts


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class Recon(BaseModule):
    name = "recon"
    description = "Unified recon: discovery, ports, traceroute, banners, fingerprint, SNMP"
    category = "recon"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(
                name="target",
                type="str",
                label="Target IP or subnet",
                required=True,
                description="192.168.1.1 → scan .1-.255; or CIDR / range",
            ),
            ModuleParam(
                name="interface",
                type="interface",
                label="Interface",
                required=False,
                default=None,
            ),
            ModuleParam(
                name="arp_scan",
                type="bool",
                label="ARP scan",
                required=False,
                default=False,
                description="One ARP per IP across full range (CIDR or start-end)",
            ),
            ModuleParam(
                name="discovery",
                type="bool",
                label="Host discovery",
                required=False,
                default=False,
                description="ARP + ICMP live-host discovery",
            ),
            ModuleParam(
                name="ports",
                type="bool",
                label="Port scan",
                required=False,
                default=False,
                description="TCP SYN scan",
            ),
            ModuleParam(
                name="traceroute",
                type="bool",
                label="Traceroute",
                required=False,
                default=False,
            ),
            ModuleParam(
                name="banners",
                type="bool",
                label="Banner grab",
                required=False,
                default=False,
            ),
            ModuleParam(
                name="fingerprint",
                type="bool",
                label="OS fingerprint",
                required=False,
                default=False,
                description="TTL / window heuristic, not a full nmap match",
            ),
            ModuleParam(
                name="snmp",
                type="bool",
                label="SNMP enum",
                required=False,
                default=False,
            ),
            ModuleParam(
                name="ports_spec",
                type="str",
                label="Ports",
                required=False,
                default=DEFAULT_PORTS,
                description="22,80,443 or 1-1024",
            ),
            ModuleParam(
                name="snmp_community",
                type="str",
                label="SNMP community",
                required=False,
                default="public",
            ),
            ModuleParam(
                name="max_ttl",
                type="int",
                label="Traceroute max TTL",
                required=False,
                default=16,
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
        flags = (
            "arp_scan",
            "discovery",
            "ports",
            "traceroute",
            "banners",
            "fingerprint",
            "snmp",
        )
        selected = [name for name in flags if _truthy(params.get(name))]
        if not selected:
            raise ValueError(
                "Select at least one technique flag: "
                "arp_scan, discovery, ports, traceroute, banners, fingerprint, snmp"
            )

        target = params["target"]
        iface = params.get("interface") or None
        if iface:
            conf.iface = iface
        conf.verb = 0

        print(f"[recon] target={target} iface={iface} techniques={','.join(selected)}")
        live: list[dict[str, str]] = []

        if "arp_scan" in selected:
            live = self._arp_scan(target, iface, logger, rate_limiter)

        if "discovery" in selected:
            found = self._discovery(target, iface, logger, rate_limiter)
            seen = {h["ip"] for h in live}
            for host in found:
                if host["ip"] not in seen:
                    live.append(host)

        hosts = [h["ip"] for h in live] if live else iter_hosts(target)
        if "ports" in selected or "banners" in selected or "fingerprint" in selected:
            hosts = hosts[:MAX_HOSTS]

        open_map: dict[str, list[int]] = {}
        if "ports" in selected:
            ports = parse_ports(str(params.get("ports_spec") or DEFAULT_PORTS))
            for host in hosts:
                if self.should_stop():
                    break
                open_map[host] = self._portscan(host, ports, iface, logger, rate_limiter)

        if "traceroute" in selected:
            # Traceroute is meaningful for a single destination.
            dest = hosts[0] if len(hosts) == 1 else target.split("/")[0]
            try:
                dest = str(ipaddress.ip_address(dest))
            except ValueError:
                dest = hosts[0]
            self._traceroute(
                dest, iface, int(params.get("max_ttl", 16)), logger, rate_limiter
            )

        if "banners" in selected:
            ports = parse_ports(str(params.get("ports_spec") or DEFAULT_PORTS))
            for host in hosts:
                if self.should_stop():
                    break
                use = open_map.get(host) or ports[:8]
                self._banners(host, use, logger)

        if "fingerprint" in selected:
            for host in hosts:
                if self.should_stop():
                    break
                self._fingerprint(host, iface, logger, rate_limiter)

        if "snmp" in selected:
            community = str(params.get("snmp_community") or "public")
            for host in hosts:
                if self.should_stop():
                    break
                self._snmp(host, community, iface, logger, rate_limiter)

        print("[recon] Done")

    def _arp_scan(self, target, iface, logger, rate_limiter) -> list[dict[str, str]]:
        hosts = network_hosts(target)
        print()
        print("── ARP scan ──")
        print(f"  Range            {target}")
        print(f"  Addresses        {len(hosts)}")
        if hosts:
            print(f"  From             {hosts[0]}")
            print(f"  To               {hosts[-1]}")
        print(f"  Interface        {iface or 'auto'}")
        found: list[dict[str, str]] = []
        seen: set[str] = set()
        for i, host in enumerate(hosts, 1):
            if self.should_stop():
                print("  ! Stopped by user")
                break
            rate_limiter.wait()
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host)
            answered, _ = srp(packet, timeout=PROBE_TIMEOUT, verbose=0)
            logger.add_packets(1, len(bytes(packet)))
            for _, rcv in answered:
                ip, mac = rcv.psrc, rcv.hwsrc
                if ip not in seen:
                    seen.add(ip)
                    found.append({"ip": ip, "mac": mac})
                    print(f"  live  {ip:<15}  MAC {mac}")
            if i % 50 == 0 or i == len(hosts):
                print(f"  progress {i}/{len(hosts)}  found {len(found)}")
        print(f"  Total live: {len(found)} / {len(hosts)}")
        return found


    def _discovery(self, target, iface, logger, rate_limiter) -> list[dict[str, str]]:
        print("[recon] discovery")
        found: list[dict[str, str]] = []
        try:
            network = ipaddress.ip_network(target, strict=False)
            pdst = str(network if network.num_addresses > 1 else network.network_address)
        except ValueError:
            pdst = target

        rate_limiter.wait()
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst),
            timeout=PROBE_TIMEOUT,
            verbose=0,
            iface=iface,
        )
        logger.add_packets(1 + len(answered), 64 * (1 + len(answered)))
        seen: set[str] = set()
        for _, rcv in answered:
            if rcv.psrc not in seen:
                seen.add(rcv.psrc)
                found.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
                print(f"  live {rcv.psrc}  {rcv.hwsrc}  (arp)")

        # ICMP sweep for hosts ARP missed (capped).
        for host in iter_hosts(target):
            if self.should_stop():
                break
            if host in seen:
                continue
            rate_limiter.wait()
            pkt = IP(dst=host) / ICMP()
            ans, _ = sr(pkt, timeout=PROBE_TIMEOUT, verbose=0)
            logger.add_packets(1, len(bytes(pkt)))
            if ans:
                seen.add(host)
                found.append({"ip": host, "mac": ""})
                print(f"  live {host}  (icmp)")
        print(f"  discovery: {len(found)} host(s)")
        return found

    def _portscan(self, host, ports, iface, logger, rate_limiter) -> list[int]:
        print(f"[recon] ports {host} ({len(ports)})")
        open_ports: list[int] = []
        for port in ports:
            if self.should_stop():
                break
            rate_limiter.wait()
            sport = random.randint(1024, 65535)
            pkt = IP(dst=host) / TCP(sport=sport, dport=port, flags="S")
            ans, _ = sr(pkt, timeout=PROBE_TIMEOUT, verbose=0)
            logger.add_packets(1, len(bytes(pkt)))
            if ans and ans[0][1].haslayer(TCP) and ans[0][1][TCP].flags & 0x12:
                open_ports.append(port)
                from scapy.all import send

                send(
                    IP(dst=host) / TCP(sport=sport, dport=port, flags="R"),
                    verbose=0,
                    iface=iface,
                )
                print(f"  {host}:{port}/tcp open")
        if not open_ports:
            print(f"  {host}: no open ports in the selected set")
        return open_ports

    def _traceroute(self, dest, iface, max_ttl, logger, rate_limiter) -> None:
        print(f"[recon] traceroute {dest}")
        max_ttl = max(1, min(int(max_ttl), 32))
        for ttl in range(1, max_ttl + 1):
            if self.should_stop():
                break
            rate_limiter.wait()
            pkt = IP(dst=dest, ttl=ttl) / ICMP()
            ans, _ = sr(pkt, timeout=PROBE_TIMEOUT, verbose=0)
            logger.add_packets(1, len(bytes(pkt)))
            if not ans:
                print(f"  {ttl:2d}  *")
                continue
            hop = ans[0][1].src
            print(f"  {ttl:2d}  {hop}")
            if hop == dest:
                break

    def _banners(self, host: str, ports: list[int], logger) -> None:
        print(f"[recon] banners {host}")
        probes = {
            80: b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
            25: b"EHLO lab.local\r\n",
            110: b"QUIT\r\n",
            143: b"a1 CAPABILITY\r\n",
        }
        for port in ports:
            if self.should_stop():
                break
            try:
                with socket.create_connection((host, port), timeout=2.0) as sock:
                    sock.settimeout(2.0)
                    probe = probes.get(port, b"")
                    if probe:
                        sock.sendall(probe)
                    data = sock.recv(512)
            except OSError as exc:
                print(f"  {host}:{port}  no banner ({exc.__class__.__name__})")
                continue
            text = data.decode("utf-8", errors="replace").strip().splitlines()
            line = text[0][:160] if text else "(empty)"
            print(f"  {host}:{port}  {line}")
            logger.add_packets(1, len(data))

    def _fingerprint(self, host, iface, logger, rate_limiter) -> None:
        print(f"[recon] fingerprint {host}")
        rate_limiter.wait()
        pkt = IP(dst=host) / TCP(dport=80, flags="S")
        ans, _ = sr(pkt, timeout=PROBE_TIMEOUT, verbose=0)
        logger.add_packets(1, len(bytes(pkt)))
        if not ans:
            rate_limiter.wait()
            pkt = IP(dst=host) / ICMP()
            ans, _ = sr(pkt, timeout=PROBE_TIMEOUT, verbose=0)
            logger.add_packets(1, len(bytes(pkt)))
        if not ans:
            print("  no reply")
            return
        reply = ans[0][1]
        ttl = int(reply[IP].ttl)
        window = int(reply[TCP].window) if reply.haslayer(TCP) else None
        guess = "unknown"
        if ttl <= 64:
            guess = "likely Linux/BSD/network appliance (initial TTL 64)"
        elif ttl <= 128:
            guess = "likely Windows (initial TTL 128)"
        elif ttl <= 255:
            guess = "likely network device (initial TTL 255)"
        extra = f", window={window}" if window is not None else ""
        print(f"  ttl={ttl}{extra}  {guess}")

    def _snmp(self, host, community, iface, logger, rate_limiter) -> None:
        print(f"[recon] snmp {host} community={community}")
        try:
            from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind
            from scapy.asn1.asn1 import ASN1_OID
        except Exception as exc:  # noqa: BLE001
            print(f"  SNMP layer unavailable: {exc}")
            return
        rate_limiter.wait()
        pkt = (
            IP(dst=host)
            / UDP(sport=random.randint(1024, 65535), dport=161)
            / SNMP(
                community=community,
                PDU=SNMPget(
                    varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]
                ),
            )
        )
        ans, _ = sr(pkt, timeout=PROBE_TIMEOUT, verbose=0)
        logger.add_packets(1, len(bytes(pkt)))
        if not ans:
            print("  no SNMP response")
            return
        print(f"  response from {ans[0][1].src}: {ans[0][1].summary()}")
