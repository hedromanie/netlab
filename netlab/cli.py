"""NetLab command-line interface (Typer)."""

from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from netlab.core import Engine, require_admin

app = typer.Typer(
    name="netlab",
    help="Educational network attack lab platform",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


@app.command("list")
def list_modules() -> None:
    """List all available attack modules."""
    engine = Engine()
    modules = engine.list_modules()

    table = Table(title="Available Modules")
    table.add_column("Name", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Description")

    for m in modules:
        table.add_row(m["name"], m["category"], m["description"])

    console.print(table)


@app.command("info")
def module_info(name: str = typer.Argument(..., help="Module name")) -> None:
    """Show detailed information about a module (including parameters)."""
    engine = Engine()
    modules = {m["name"]: m for m in engine.list_modules()}
    if name not in modules:
        console.print(f"[red]Unknown module: {name}[/red]")
        raise typer.Exit(1)

    m = modules[name]
    console.print(f"[bold]{m['name']}[/bold]  ({m['category']})")
    console.print(m["description"])
    console.print()

    if not m["parameters"]:
        console.print("No parameters.")
        return

    table = Table(title="Parameters")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Required")
    table.add_column("Default")
    table.add_column("Description")

    for p in m["parameters"]:
        table.add_row(
            p["name"],
            p["type"],
            "yes" if p["required"] else "no",
            str(p["default"]) if p["default"] is not None else "—",
            p["description"],
        )
    console.print(table)


@app.command("run")
def run_module(
    name: str = typer.Argument(..., help="Module name"),
    param: Optional[list[str]] = typer.Option(
        None,
        "--param",
        "-p",
        help="Parameter in form key=value (can be repeated)",
    ),
    rate_limit: Optional[float] = typer.Option(
        None,
        "--rate-limit",
        "-r",
        help="Packets per second limit (0 = unlimited)",
    ),
) -> None:
    """Run an attack module."""
    require_admin()

    params: dict = {}
    if param:
        for item in param:
            if "=" not in item:
                console.print(f"[red]Invalid parameter format: {item} (expected key=value)[/red]")
                raise typer.Exit(1)
            k, v = item.split("=", 1)
            params[k.strip()] = v.strip()

    engine = Engine()
    console.print(f"[bold]Starting module[/bold] [cyan]{name}[/cyan] ...")

    try:
        logger = engine.run_module(name, params, rate_limit_pps=rate_limit)
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)

    console.print()
    console.print(f"[green]Finished[/green] — status: {logger.status}")
    console.print(f"Packets sent : {logger.packets_sent}")
    console.print(f"Bytes sent   : {logger.bytes_sent}")
    if logger.path:
        console.print(f"Log file     : {logger.path}")


@app.command("recon")
def recon_cmd(
    target: str = typer.Argument(..., help="IP or subnet, e.g. 192.168.1.10 or 192.168.1.0/24"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i"),
    discovery: bool = typer.Option(False, "--discovery", help="ARP + ICMP host discovery"),
    arp_scan: bool = typer.Option(False, "--arp-scan", help="ARP request to every IP in the network"),
    ports: bool = typer.Option(False, "--ports", help="TCP SYN port scan"),
    traceroute: bool = typer.Option(False, "--traceroute", help="TTL traceroute"),
    banners: bool = typer.Option(False, "--banners", help="Grab service banners"),
    fingerprint: bool = typer.Option(False, "--fingerprint", help="Rough OS fingerprint"),
    snmp: bool = typer.Option(False, "--snmp", help="SNMPv1 sysDescr"),
    ports_spec: str = typer.Option(
        "21,22,23,25,53,80,110,135,139,143,443,445,3389,8080",
        "--ports-spec",
        help="Port list or range",
    ),
    snmp_community: str = typer.Option("public", "--community"),
    max_ttl: int = typer.Option(16, "--max-ttl"),
    rate_limit: Optional[float] = typer.Option(None, "--rate-limit", "-r"),
) -> None:
    """Run reconnaissance. Each technique is its own flag."""
    require_admin()
    if not any((discovery, arp_scan, ports, traceroute, banners, fingerprint, snmp)):
        console.print(
            "[red]Pick at least one flag:[/red] "
            "--arp-scan --discovery --ports --traceroute --banners --fingerprint --snmp"
        )
        raise typer.Exit(1)

    params = {
        "target": target,
        "interface": interface,
        "arp_scan": arp_scan,
        "discovery": discovery,
        "ports": ports,
        "traceroute": traceroute,
        "banners": banners,
        "fingerprint": fingerprint,
        "snmp": snmp,
        "ports_spec": ports_spec,
        "snmp_community": snmp_community,
        "max_ttl": max_ttl,
    }
    engine = Engine()
    console.print(f"[bold]recon[/bold] {target}")
    try:
        logger = engine.run_module("recon", params, rate_limit_pps=rate_limit)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]{logger.status}[/green]  log={logger.path}")


@app.command("gui")
def gui_cmd() -> None:
    """Open the desktop GUI."""
    from netlab.gui import main

    main()


@app.command("version")
def version() -> None:
    """Show version."""
    from netlab import __version__
    console.print(f"netlab {__version__}")


if __name__ == "__main__":
    app()
