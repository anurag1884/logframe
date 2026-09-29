SAMPLE_CEF_LOGS = [
    "CEF:0|Cisco|ASA|9.1|106023|Deny Inbound TCP|5|src=192.168.1.10 spt=54321 dst=8.8.8.8 dpt=443 proto=TCP shost=client01 dhost=dns.google app=https",
    "CEF:0|Palo Alto Networks|PAN-OS|10.2|threat/url|ALLOW Outbound DNS|3|src=10.0.0.45 spt=51234 dst=1.1.1.1 dpt=53 proto=UDP shost=workstation22 dhost=one.one.one.one app=dns requestURL=https://one.one.one.one/dns-query",
    "CEF:0|Fortinet|FortiGate|7.0.1|0000000013|DENY Inbound ICMP|7|src=203.0.113.55 dst=10.10.10.1 proto=ICMP deviceDirection=1 deviceExternalId=FGT60E-0001",
    "CEF:0|Cisco|ASA|9.1|106100|ACCEPT Outbound HTTP|2|src=172.16.0.20 spt=49876 dst=93.184.216.34 dpt=80 proto=TCP shost=devbox.internal app=http bytesOut=15230 bytesIn=82400",
    "CEF:0|Juniper|SRX345|21.4R1|RT_FLOW_SESSION_DENY|Deny Unknown Protocol|9|src=198.51.100.77 spt=0 dst=192.0.2.5 dpt=0 proto=HOPOPT deviceInboundInterface=ge-0/0/0 deviceOutboundInterface=ge-0/0/1 reason=policy-deny",
    "CEF:0|Check Point|Firewall-1 R81|R81.10|drop|DENY Lateral Movement Attempt|10|src=10.20.30.40 spt=445 dst=10.20.30.99 dpt=445 proto=TCP shost=compromised-host dhost=target-host app=msrpc-base msg=SMB\\ lateral\\ movement\\ blocked cs1=SentinelPolicy cs1Label=Policy Name",
    "CEF:0|Fortinet|FortiGate|7.0.1|0000000026|ACCEPT VPN Tunnel Established|4|src=203.0.113.10 spt=4500 dst=192.168.100.1 dpt=4500 proto=UDP app=ike tunnelType=IPsec vpnTunnel=HQ-Branch-01 reason=tunnel-up",
    "CEF:0|Cisco|ASA|9.1|302013|Deny Outbound TCP No Route|0|src=192.168.2.200 spt=61000 dst=10.255.255.255 dpt=8080 proto=TCP deviceExternalId=ASA-DMZ-02 outcome=failure",
]
