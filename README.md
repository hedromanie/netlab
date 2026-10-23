# NetForge

Учебный стенд сетевых атак (L2–L4 и пара прикладных техник). Только изолированная лаборатория. MIT.

## Запуск

```bash
cd NetForge
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e .

# CLI
netlab list
netlab recon 192.168.1.0/24 --arp-scan --discovery --ports --fingerprint

# Desktop GUI (категории, темы, RU/EN, справка, вкл/выкл логов)
netlab gui
```

Нужны права администратора / root и Npcap (Windows) или libpcap (Linux).

Интерфейс определяется автоматически. Web-интерфейс удалён.

## Модули

| Модуль | Уровень |
|---|---|
| recon | разведка, флаги техник |
| arp_spoof, dhcp_starvation, mac_flood, rogue_dhcp | L2 |
| ip_spoof, tcp_reset, dns_spoof, dns_amp, syn/udp/icmp flood | L3/L4 |
| ssl_strip, llmnr_poison | прикладной |

Описание настроек и механики: [docs/attacks.md](docs/attacks.md).
