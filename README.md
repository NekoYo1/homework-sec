# Домашнее задание к занятию "Уязвимости и атаки на информационные системы" - `Филиппов К.П`


---

### Задание 1

Сетевые службы

    FTP — vsftpd 2.3.4 (21)

    SSH — OpenSSH 4.7p1 (22)

    Telnet — (23)

    SMTP — Postfix (25)

    DNS — (53)

    HTTP — Apache 2.2.8 (80)

    Samba — (139/445)

    MySQL — (3306)

    PostgreSQL — (5432)

    VNC — (5900)

    UnrealIRCd — (6667)

    Tomcat — (8180)

Уязвимости

    vsftpd 2.3.4 — Backdoor Command Execution (CVE-2011-2523)
    Порт: 21
    Exploit-DB 17491

    Samba 3.x — Username Map Script Command Injection (CVE-2007-2447)
    Порты: 139/445
    Exploit-DB 16320

    UnrealIRCd 3.2.8.1 — Backdoor Command Execution (CVE-2010-2075)
    Порт: 6667
    Exploit-DB 13853

---

### Задание 2

Режимы сканирования 

    SYN (-sS) — флаги: SYN; открытый порт: SYN/ACK; закрытый порт: RST.

    FIN (-sF) — флаги: FIN; открытый порт: нет ответа; закрытый порт: RST.

    Xmas (-sX) — флаги: FIN+PSH+URG; открытый порт: нет ответа; закрытый порт: RST.

    UDP (-sU) — флаги: UDP-датаграмма; открытый порт: нет ответа (open|filtered); закрытый порт: ICMP Port Unreachable.

Отличия и ответы сервера

    SYN — единственный режим, который устанавливает полуоткрытое соединение и получает SYN/ACK. Надёжно различает open/closed/filtered.

    FIN и Xmas — «стелс»-сканы. Не завершают TCP-рукопожатие. Открытые порты обычно игнорируют пакеты, закрытые отвечают RST.

    UDP — не использует TCP-флаги. Открытые порты чаще молчат, закрытые возвращают ICMP Port Unreachable.



    SYN — tcp.flags.syn == 1 && tcp.flags.ack == 0

    SYN/ACK — tcp.flags.syn == 1 && tcp.flags.ack == 1

    RST — tcp.flags.reset == 1

    FIN — tcp.flags.fin == 1

    Xmas — tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1

    UDP — udp

    ICMP — icmp.type == 3

Фильтр захвата: host <IP_metasploitable>. Для разбора использовались фильтры tcp.flags.syn, tcp.flags.reset, tcp.flags.fin, tcp.flags.push, tcp.flags.urg, udp, icmp.type == 3.

---

