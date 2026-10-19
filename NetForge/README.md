# NetForge

Educational network attack lab platform (L2–L4).

**Status:** v0.1.0 — working attack modules (Scapy), CLI + API ready

## Features

- Plugin-based attack modules (auto-discovery)
- CLI (Typer) + REST API (FastAPI)
- JSON audit logging (packets, bytes, duration, full parameters)
- Configurable rate limiting on every module
- Windows-first (Npcap), Linux later
- Strict professional style, MIT license

## Modules

| Module            | Category | Status                          |
|-------------------|----------|---------------------------------|
| host_discovery    | recon    | ✅ Working (ARP + ICMP)         |
| port_scan         | recon    | ✅ Working (TCP SYN)            |
| arp_spoof         | l2       | ✅ Working (with restore)       |
| dhcp_starvation   | l2       | ✅ Working                      |
| dns_spoof         | l3_l4    | ✅ Working (needs MITM path)    |
| syn_flood         | l3_l4    | ✅ Working (Scapy, rate-limited)|
| udp_flood         | l3_l4    | ✅ Working (Scapy, rate-limited)|
| icmp_flood        | l3_l4    | ✅ Working (Scapy, rate-limited)|

> Flood modules currently use Scapy. Native C++ backends are planned for higher PPS.

## Requirements

- Python 3.11+
- Administrator / root privileges
- Npcap (Windows) or libpcap (Linux)
- `pip install -e .`

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate

pip install -e .

# List modules
netlab list

# Module details
netlab info arp_spoof

# Run (example)
netlab run host_discovery -p target=192.168.1.0/24
netlab run arp_spoof -p victim=192.168.1.50 -p gateway=192.168.1.1 -p interface=eth0 -p duration=30

# Web API
uvicorn netlab.web:app --reload --host 127.0.0.1 --port 8000
```

## Project structure

```
netlab/                 # Python package
  core.py               # Engine, config, rate limiter, privileges
  logger.py             # JSON audit logger
  base.py               # BaseModule + plugin discovery
  cli.py                # Typer CLI
  web.py                # FastAPI backend
  modules/              # Attack plugins (auto-discovered)
native/                 # C++ flood engines (skeleton)
configs/                # YAML configuration
logs/                   # Attack audit logs (auto-created)
web-frontend/           # React UI (next)
```

## Priority roadmap

1. ✅ Foundation + all core modules on Scapy
2. React frontend (list + dynamic forms + run)
3. Native C++ floods + pybind11
4. Config editor in Web UI
5. Polish (Npcap detection, log history, docs)

## License

MIT
