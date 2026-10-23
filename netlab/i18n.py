"""UI strings and the in-app attack reference."""

from __future__ import annotations

CATEGORIES = {
    "en": {
        "recon": "Reconnaissance",
        "l2": "Layer 2",
        "l3_l4": "Layer 3 / 4",
        "app": "Application",
        "misc": "Other",
    },
    "ru": {
        "recon": "Разведка",
        "l2": "Канальный уровень",
        "l3_l4": "Сетевой / транспорт",
        "app": "Прикладной уровень",
        "misc": "Прочее",
    },
}

UI = {
    "en": {
        "settings": "Settings",
        "help": "Help",
        "run": "Run",
        "stop": "Stop",
        "language": "Language",
        "theme": "Theme",
        "save_logs": "Save JSON logs",
        "apply": "Apply",
        "close": "Close",
        "select": "Select a module",
        "not_admin": "Not running as Administrator/root. Packet modules will fail until you relaunch elevated.\n",
        "logs_off": "logs are not saved",
        "stop_req": "\n[stop requested]\n",
        "themes": {"dark": "Dark", "light": "Light", "nord": "Nord"},
    },
    "ru": {
        "settings": "Настройки",
        "help": "Справка",
        "run": "Запуск",
        "stop": "Стоп",
        "language": "Язык",
        "theme": "Тема",
        "save_logs": "Сохранять JSON-логи",
        "apply": "Применить",
        "close": "Закрыть",
        "select": "Выберите модуль",
        "not_admin": "Нет прав администратора или root. Модули с пакетами не заработают, пока процесс не запущен с повышением.\n",
        "logs_off": "логи не сохраняются",
        "stop_req": "\n[запрошена остановка]\n",
        "themes": {"dark": "Тёмная", "light": "Светлая", "nord": "Nord"},
    },
}

PARAM_RU = {
    "target": "Цель",
    "victim": "Жертва",
    "gateway": "Шлюз",
    "duration": "Длительность (сек)",
    "rate_limit_pps": "Лимит, пакетов/с",
    "count": "Количество",
    "port": "Порт",
    "ports": "Скан портов",
    "ports_spec": "Список портов",
    "protocol": "Протокол",
    "source": "Поддельный IP источника",
    "listen_port": "Порт прокси",
    "respond_ip": "IP в ответе",
    "name_filter": "Фильтр имени",
    "pool_start": "Начало пула",
    "dns": "DNS",
    "subnet": "Маска сети",
    "server_ip": "IP этого DHCP-сервера",
    "lease": "Аренда (сек)",
    "query_name": "Имя в запросе",
    "qtype": "Тип запроса",
    "resolver": "DNS-резолвер",
    "target_domain": "Домен",
    "fake_ip": "Поддельный IP",
    "arp_scan": "ARP scan",
    "discovery": "Поиск хостов",
    "traceroute": "Traceroute",
    "banners": "Баннеры",
    "fingerprint": "Отпечаток ОС",
    "snmp": "SNMP",
    "snmp_community": "Community SNMP",
    "max_ttl": "Максимальный TTL",
}

HELP = {
    "en": """
<h2>NetForge reference</h2>
<p>Every module picks the network interface itself from the default IPv4 route. Logs, if enabled in Settings, land in <code>logs/</code> as JSON: parameters, packets, bytes, duration.</p>
<h3>recon</h3>
<p><b>How.</b> One module, several flags. ARP scan sends a separate ARP who-has to every address in the subnet. Discovery is a broadcast ARP plus ICMP. Ports is a TCP SYN scan. Traceroute raises TTL. Banners read the first bytes of a service. Fingerprint guesses the OS from the TTL (64 Linux-like, 128 Windows-like, 255 network gear). SNMP asks for sysDescr.0.</p>
<p><b>Result.</b> A list of live hosts, open ports, hops, banners or a rough OS guess. Nothing on the target is changed except the probe packets.</p>
<h3>arp_spoof</h3>
<p><b>How.</b> The victim is told that the gateway's MAC is ours, and the gateway is told that the victim's MAC is ours. On exit the real MACs are restored.</p>
<p><b>Result.</b> Traffic between those two hosts is redirected through this machine for the chosen duration.</p>
<h3>dhcp_starvation</h3>
<p><b>How.</b> Many DHCP DISCOVER packets, each with a new MAC.</p>
<p><b>Result.</b> The lab DHCP server leases out addresses until the pool is empty and new clients stop getting an address.</p>
<h3>mac_flood</h3>
<p><b>How.</b> Ethernet frames with a fresh random source MAC, capped at 20000.</p>
<p><b>Result.</b> The switch CAM table fills up. After that the switch floods frames out of every port, like a hub.</p>
<h3>rogue_dhcp</h3>
<p><b>How.</b> Listens on UDP/67. DISCOVER gets an OFFER, REQUEST gets an ACK, both advertising our gateway and DNS.</p>
<p><b>Result.</b> A client that accepts the offer uses our gateway and DNS. The real server on the same segment races us. On Windows this needs Administrator and Npcap.</p>
<h3>ip_spoof</h3>
<p><b>How.</b> A real TCP, UDP or ICMP packet is sent with a source address that is not ours. Cap is 2000 packets.</p>
<p><b>Result.</b> The destination answers the spoofed address, not this host. There is no local reply.</p>
<h3>tcp_reset</h3>
<p><b>How.</b> Sniffs TCP involving the target and injects a RST using the acknowledgement number it just saw.</p>
<p><b>Result.</b> The receiver closes that connection.</p>
<h3>dns_spoof</h3>
<p><b>How.</b> A DNS query for the chosen name is answered immediately with a fake A record. This only works if the query passes through us, usually after ARP spoofing.</p>
<p><b>Result.</b> The client resolves that name to the fake IP.</p>
<h3>dns_amp</h3>
<p><b>How.</b> A query is sent to a resolver with the victim's address as the source, so the larger answer is reflected to the victim. Hard cap: 50 queries and 10 per second.</p>
<p><b>Result.</b> The victim receives DNS answers it did not ask for. This host does not see those answers.</p>
<h3>syn_flood / udp_flood / icmp_flood</h3>
<p><b>How.</b> A rate-limited stream of SYN, UDP or ICMP echo packets.</p>
<p><b>Result.</b> The target spends resources on half-open connections or on answering. The log shows how many packets left this host.</p>
<h3>ssl_strip</h3>
<p><b>How.</b> A local HTTP proxy. It fetches the site over HTTPS and rewrites https:// links to http://. CONNECT is refused. TLS is not broken.</p>
<p><b>Result.</b> A client forced through the proxy keeps speaking cleartext HTTP, so a MITM can read the session. You still need ARP spoofing or an explicit proxy setting.</p>
<h3>llmnr_poison</h3>
<p><b>How.</b> Answers LLMNR (UDP 5355) and NetBIOS-NS (UDP 137) with our IP. Optional name filter. It does not relay credentials.</p>
<p><b>Result.</b> A Windows host that asked for that name connects to us instead of the real host.</p>
""",
    "ru": """
<h2>Справка NetForge</h2>
<p>Интерфейс для каждой атаки выбирается сам: тот, через который идёт маршрут к 8.8.8.8. Если в настройках включены логи, они пишутся в <code>logs/</code> в JSON: параметры, пакеты, байты, время.</p>
<h3>recon</h3>
<p><b>Как работает.</b> Один модуль и отдельные флаги. ARP scan шлёт отдельный ARP who-has на каждый адрес заданной сети. Discovery — широковещательный ARP плюс ICMP. Ports — TCP SYN. Traceroute поднимает TTL. Banners читает первые байты сервиса. Fingerprint оценивает ОС по TTL: 64 похоже на Linux, 128 на Windows, 255 на сетевое железо. SNMP запрашивает sysDescr.0.</p>
<p><b>Результат.</b> Список живых хостов, открытых портов, хопов, баннеров или грубая оценка ОС. На цели ничего не меняется, кроме самих проб.</p>
<h3>arp_spoof</h3>
<p><b>Как работает.</b> Жертве сообщаем, что MAC шлюза — наш, шлюзу — что MAC жертвы наш. При остановке возвращаем настоящие MAC.</p>
<p><b>Результат.</b> Трафик между этими двумя хостами идёт через эту машину, пока идёт атака.</p>
<h3>dhcp_starvation</h3>
<p><b>Как работает.</b> Много DHCP DISCOVER, у каждого новый MAC.</p>
<p><b>Результат.</b> Лабораторный DHCP-сервер раздаёт адреса, пока пул не опустеет. Новые клиенты адрес не получают.</p>
<h3>mac_flood</h3>
<p><b>Как работает.</b> Кадры Ethernet со случайным MAC источника. Потолок — 20000 кадров.</p>
<p><b>Результат.</b> CAM-таблица свитча заполняется. Дальше свитч рассылает чужие кадры во все порты, как хаб.</p>
<h3>rogue_dhcp</h3>
<p><b>Как работает.</b> Слушаем UDP/67. На DISCOVER уходит OFFER, на REQUEST — ACK, в них наш шлюз и DNS.</p>
<p><b>Результат.</b> Клиент, который принял ответ, использует наш шлюз и DNS. Настоящий сервер в том же сегменте отвечает одновременно. На Windows нужны права администратора и Npcap.</p>
<h3>ip_spoof</h3>
<p><b>Как работает.</b> В сеть уходит настоящий TCP, UDP или ICMP, но адрес источника чужой. Потолок — 2000 пакетов.</p>
<p><b>Результат.</b> Цель отвечает поддельному адресу, не этой машине. Локального ответа не будет.</p>
<h3>tcp_reset</h3>
<p><b>Как работает.</b> Сниффим TCP с участием цели и вставляем RST с номером, который только что увидели в подтверждении.</p>
<p><b>Результат.</b> Получатель закрывает это соединение.</p>
<h3>dns_spoof</h3>
<p><b>Как работает.</b> На запрос нужного имени сразу уходит ответ с поддельным A. Сработает, только если запрос проходит через нас, обычно после ARP spoof.</p>
<p><b>Результат.</b> Клиент считает, что это имя указывает на поддельный IP.</p>
<h3>dns_amp</h3>
<p><b>Как работает.</b> Запрос к резолверу уходит с адресом жертвы в source, поэтому большой ответ летит жертве. Жёсткий потолок: 50 запросов и 10 в секунду.</p>
<p><b>Результат.</b> Жертва получает DNS-ответы, которые не запрашивала. Эта машина сами ответы не видит.</p>
<h3>syn_flood / udp_flood / icmp_flood</h3>
<p><b>Как работает.</b> Поток SYN, UDP или ICMP echo. Скорость режется лимитом.</p>
<p><b>Результат.</b> Цель тратит ресурсы на полуоткрытые соединения или на ответы. В логе видно, сколько пакетов ушло отсюда.</p>
<h3>ssl_strip</h3>
<p><b>Как работает.</b> Локальный HTTP-прокси. Сайт забирается по HTTPS, в ответе https:// меняется на http://. CONNECT отвергается. Сам TLS не ломается.</p>
<p><b>Результат.</b> Клиент, которого направили в прокси, остаётся на открытом HTTP, и промежуточный узел читает сессию. ARP spoof или явная настройка прокси всё равно нужны.</p>
<h3>llmnr_poison</h3>
<p><b>Как работает.</b> На LLMNR (UDP 5355) и NetBIOS-NS (UDP 137) отвечаем своим IP. Можно ограничить имя. Учётные данные модуль не перехватывает и не ретранслирует.</p>
<p><b>Результат.</b> Windows-хост, который спросил это имя, подключается к нам, а не к настоящему узлу.</p>
""",
}


def param_label(lang: str, name: str, fallback: str) -> str:
    if lang == "ru":
        return PARAM_RU.get(name, fallback)
    return fallback
