from scapy.all import IPv6, ICMPv6EchoRequest, Ether, sendp  

# Nastavení cílové IPv6 adresy
target_ip = "2001:db8::1"
target_mac = "00:1a:2b:3c:4d:5e"

# Vytvoření a odeslání ICMPv6 Echo Request paketu
packet = Ether(dst=target_mac) / IPv6(dst=target_ip) / ICMPv6EchoRequest()
sendp(packet)

