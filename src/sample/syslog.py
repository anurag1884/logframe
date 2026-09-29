SAMPLE_SYSLOGS = [
    # RFC 3164
    "<134>Sep 22 14:05:31 firewall01 firewall: SRC=192.168.1.10 SPT=54321 DST=8.8.8.8 DPT=443 PROTO=TCP",
    "<132>Sep 22 14:06:12 firewall01 firewall: SRC=10.0.0.15 SPT=51520 DST=172.217.160.46 DPT=443 PROTO=TCP",
    "<130>Sep 22 14:07:45 firewall01 firewall: SRC=192.168.1.25 SPT=49211 DST=10.10.10.5 DPT=22 PROTO=TCP",
    "<134>Sep 22 14:08:03 router01 kernel: SRC=192.168.1.50 SPT=5432 DST=192.168.1.1 DPT=53 PROTO=UDP",
    "<131>Sep 22 14:09:18 firewall02 security: SRC=203.0.113.50 SPT=445 DST=192.168.1.20 DPT=445 PROTO=TCP",
    # RFC 3164 with other message styles
    "<134>Sep 22 14:10:21 server01 sshd[4521]: Accepted password for admin from 192.168.1.50",
    "<131>Sep 22 14:11:02 server01 sshd[4521]: Failed password for admin from 10.0.0.25",
    "<134>Sep 22 14:12:33 router01 network: src=10.0.0.10 src_port=5000 dst=10.0.0.20 dst_port=8080 protocol=TCP",
    # RFC 5424
    "<134>1 2026-09-22T14:15:31Z firewall01 firewall 4521 ID47 - SRC=192.168.1.10 SPT=54321 DST=8.8.8.8 DPT=443 PROTO=TCP",
    "<132>1 2026-09-22T14:16:12Z firewall01 firewall 4522 ID48 - SRC=10.0.0.15 SPT=51520 DST=172.217.160.46 DPT=443 PROTO=TCP",
    "<130>1 2026-09-22T14:17:45Z firewall01 firewall 4523 ID49 - SRC=192.168.1.25 SPT=49211 DST=10.10.10.5 DPT=22 PROTO=TCP",
    # RFC 5424 with structured data
    '<134>1 2026-09-22T14:18:03Z firewall01 firewall 4524 ID50 [event iut="3" eventSource="firewall"] SRC=192.168.1.50 SPT=5432 DST=192.168.1.1 DPT=53 PROTO=UDP',
    '<132>1 2026-09-22T14:19:18Z firewall02 security 4525 ID51 [security action="deny" reason="policy"] SRC=203.0.113.50 SPT=445 DST=192.168.1.20 DPT=445 PROTO=TCP',
    # RFC 5424 with IP:PORT format
    "<134>1 2026-09-22T14:20:00Z firewall03 network 5001 ID52 - 192.168.1.100:54321 -> 8.8.8.8:443 protocol=TCP",
    # Other messages
    "<134>Sep 22 14:21:30 firewall01 firewall: Connection accepted",
    "<131>Sep 22 14:22:10 firewall01 firewall: Connection denied",
    "<135>Sep 22 14:23:55 router01 router: Interface eth0 changed state to DOWN",
]
