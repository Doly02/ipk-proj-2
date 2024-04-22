#
#   File: SendMld143.py
#   Description: Sends Single Packet MLDv1 Done (Type 132) to FF02::1
#

from scapy.all import send, IPv6, ICMPv6MLReport2

# Create IPv6 Header
src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
dst_address = 'FF02::16'  # Address for all MLDv2-capable routers

ip = IPv6(src=src_address, dst=dst_address)

# Create an MLDv2 Report message
mld = ICMPv6MLReport2()  # Create MLDv2 report message
mld.mr_type = 143  # MLDv2 report type is 143
mld.cksum = None  # Auto-calculate checksum

packet = ip/mld  # Assembly packet

# Send the packet
send(packet)  # Send packet
