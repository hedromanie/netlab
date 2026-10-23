# Атаки NetForge

Интерфейс для каждой атаки выбирается сам (маршрут по умолчанию). Поле `interface` можно не указывать.

JSON-логи в `logs/` включаются/выключаются в настройках GUI (`save_logs`). Общий предохранитель — `rate_limit_pps`. У `dns_amp`, `ip_spoof` и `mac_flood` лимит ещё и зашит в коде.

## recon

Одна команда, каждая техника — флаг. Параметра timeout нет (внутри фиксированный `PROBE_TIMEOUT`).

```bash
netlab recon 192.168.1.0/24 --arp-scan --discovery --ports --traceroute --banners --fingerprint --snmp
netlab recon 192.168.1.0-192.168.1.255 --arp-scan
```

Настройки: `target` (IP, CIDR или диапазон a-b), опционально `interface`, флаги `arp_scan` / `discovery` / `ports` / `traceroute` / `banners` / `fingerprint` / `snmp`, `ports_spec`, `snmp_community`, `max_ttl`, `rate_limit_pps`.

Как работает:
- `--arp-scan` — ARP who-has на **каждый** адрес. Для 192.168.1.0/24 это 256 адресов (.0 … .255). Также: 192.168.1.0-192.168.1.255 или 192.168.1.10-50. Потолок 4096.
- `--discovery` — широковещательный ARP плюс ICMP.
- `--ports` — TCP SYN (на открытые шлётся RST).
- `--traceroute` — ICMP с растущим TTL.
- `--banners` — первый ответ сервиса.
- `--fingerprint` — эвристика по TTL (64 ≈ Linux, 128 ≈ Windows, 255 ≈ сетевое железо).
- `--snmp` — SNMPv1 GET `sysDescr.0`.

## arp_spoof

Настройки: `victim`, `gateway`, `interface`, `duration`, `rate_limit_pps`.

Как работает: хосту жертвы говорим, что MAC шлюза — наш, шлюзу — что MAC жертвы наш. Трафик между ними идёт через нас. На выходе шлём настоящие MAC обратно.

## dhcp_starvation

Настройки: `interface`, `count`, `rate_limit_pps`.

Как работает: много DHCP DISCOVER с разными MAC. Сервер выдаёт адреса, пока пул не кончится.

## mac_flood

Настройки: `interface`, `count` (потолок 20000), `rate_limit_pps`.

Как работает: кадры Ethernet с новым случайным source MAC. CAM-таблица свитча переполняется, и он начинает рассылать кадры на все порты, как хаб.

## rogue_dhcp

Настройки: `interface`, `pool_start`, `count` (размер пула), `server_ip`, `gateway`, `dns`, `subnet`, `lease`, `duration`.

Как работает: слушаем UDP/67. На DISCOVER отвечаем OFFER, на REQUEST — ACK, со своим шлюзом и DNS. Настоящий сервер в сегменте отвечает параллельно; кто успел, того клиент и выберет.

На Windows это возможно: процесс должен быть от администратора, установлен Npcap, интерфейс — лучше Ethernet, не Wi-Fi в режиме клиента. Windows не запрещает слать сырые DHCP-ответы. Мешают гонка с легитимным сервером, firewall и адаптеры, которые не отдают raw 802.11.

## ip_spoof

Настройки: `source`, `target`, `protocol` (tcp/udp/icmp), `port`, `interface`, `count` (потолок 2000), `rate_limit_pps`.

Как работает: в заголовок IP пишется чужой source, пакет реально уходит в сеть. Ответ придёт на поддельный адрес, не на эту машину. Это не учебная «симуляция в логе».

## tcp_reset

Настройки: `target`, `port` (0 = любой), `interface`, `duration`, `rate_limit_pps`.

Как работает: сниффим TCP с участием `target` и вставляем RST с seq = ack увиденного сегмента. Получатель закрывает сокет.

## dns_spoof

Настройки: `target_domain`, `fake_ip`, `interface`, `duration`.

Как работает: ловим DNS-запрос к нужному имени и сразу шлём ответ с поддельным A-записью. Имеет смысл только если мы на пути пакета (обычно вместе с ARP spoof).

## dns_amp

Настройки: `victim`, `resolver`, `query_name`, `qtype`, `interface`, `count`, `rate_limit_pps`.

Как работает: запрос к резолверу уходит с source = адрес жертвы. Большой ответ резолвер шлёт жертве. В коде жёстко не больше 50 запросов и 10 пакетов/с, даже если в форме поставить больше.

## syn_flood, udp_flood, icmp_flood

Настройки: `target`, для TCP/UDP ещё `port`, `interface`, `duration`, `rate_limit_pps`.

Как работает: поток SYN, UDP или ICMP echo на цель. Скорость режется rate-limit. Это Scapy, не C++.

## ssl_strip

Настройки: `listen_port` (8080), `duration`.

Как работает: локальный HTTP-прокси. Запрос клиента уходит на сайт по HTTPS, в ответе `https://` заменяется на `http://`, CONNECT отвергается. Сам TLS не ломается: клиента удерживают на открытом HTTP. Нужен уже построенный MITM (ARP spoof) и чтобы HTTP жертвы шёл в этот прокси.

## llmnr_poison

Настройки: `interface`, `respond_ip`, `name_filter` (`*` или подстрока), `duration`.

Как работает: на LLMNR (UDP 5355) и NetBIOS-NS (UDP 137) отвечаем, что запрошенное имя — это `respond_ip`. Дальше клиент Windows стучится к нам. Релей учётных данных этот модуль не делает.
