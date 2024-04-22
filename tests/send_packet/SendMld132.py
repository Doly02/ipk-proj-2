#
#   File: SendMld132.py
#   Description: Sends Single Packet MLDv1 Done (Type 132) to FF02::1
#

from scapy.all import send, IPv6, ICMPv6MLDone

# Create IPv6 Header
src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
dst_address = 'FF02::1'  
ip = IPv6(src=src_address, dst=dst_address)  # FF02::1 Address For All Nodes On Local Segment


mld = ICMPv6MLDone() # Create MLD Done message


packet = ip/mld # Assembly packet

# Odeslání paketu
send(packet) # Send Packet