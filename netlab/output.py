"""Readable console lines for attacks (stdout → GUI log panel)."""

from __future__ import annotations

from typing import Any


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def header(title: str) -> None:
    print()
    print(f"── {title} ──")


def line(label: str, value: Any = "") -> None:
    if value == "" or value is None:
        print(f"  {label}")
    else:
        print(f"  {label:<16} {value}")


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def warn(msg: str) -> None:
    print(f"  ! {msg}")


def info(msg: str) -> None:
    print(f"  · {msg}")


def summary(packets: int, nbytes: int, duration: float, status: str = "готово") -> None:
    print()
    print(
        f"── Итог: {status}  ·  пакетов: {packets}  ·  "
        f"объём: {_fmt_bytes(nbytes)}  ·  время: {duration:.1f} с ──"
    )


STATUS_RU = {
    "completed": "завершено",
    "stopped": "остановлено",
    "error": "ошибка",
    "running": "работает",
}

MODULE_TITLE = {
    "recon": "Разведка",
    "arp_spoof": "ARP-подмена (MITM)",
    "dhcp_starvation": "DHCP starvation",
    "mac_flood": "MAC flooding",
    "rogue_dhcp": "Поддельный DHCP",
    "ip_spoof": "IP spoofing",
    "tcp_reset": "TCP Reset",
    "dns_spoof": "DNS spoofing",
    "dns_amp": "DNS amplification",
    "syn_flood": "SYN flood",
    "udp_flood": "UDP flood",
    "icmp_flood": "ICMP flood",
    "ssl_strip": "SSL stripping",
    "llmnr_poison": "LLMNR / NBT-NS poisoning",
}
