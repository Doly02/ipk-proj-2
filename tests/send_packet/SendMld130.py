#
#   File: SendMld130.py
#   Description: Sends MLD Packet Query (Type 130) to FF02::1
#

from scapy.all import send, IPv6, ICMPv6MLQuery

# Vytvoření základní IPv6 hlavičky
src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
dst_address = 'FF02::1'  
ip = IPv6(src=src_address, dst=dst_address)  # FF02::1 je adresa pro všechny uzly na lokálním segmentu

# Vytvoření MLD zprávy
# Type může být například 130 pro MLD Query, 131 pro MLD Report, nebo 132 pro MLD Done
mld = ICMPv6MLQuery()

# Poskládání paketu
packet = ip/mld

# Odeslání paketu
send(packet)