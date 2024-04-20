import threading
from scapy.all import send, IPv6, ICMPv6MLReport2,ICMPv6MLQuery,ICMPv6MLReport,ICMPv6MLDone
from scapy.all import ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_Redirect, ICMPv6NDOptSrcLLAddr
from scapy.all import ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo,ICMPv6NDOptDstLLAddr
from scapy.all import ARP, Ether, sendp
from scapy.all import IP, ICMP
import netifaces as ni # To get the interface IP address
import socket
import struct

def get_interface_ipv6_address(interface):
    try:
        ipv6_addr = ni.ifaddresses(interface)[ni.AF_INET6][0]['addr']
        return ipv6_addr
    except (ValueError, KeyError):
        return None

def checksum(msg):
    """
    Function for Calculation of IGMP Checksum
    """
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff


def prep_igmp_query():
    """
    Připraví IGMP Query packet.
    """
    type_igmp = 0x11                                # Type for IGMP Query
    max_resp_time = 100                             # Maximal Response in Tenths of a Second
    group_address = socket.inet_aton('0.0.0.0')     # Group Address (For General Query is 0.0.0.0)
    igmp_packet = struct.pack('!BBH4s', type_igmp, max_resp_time, 0, group_address)
    chksum = checksum(igmp_packet)
    igmp_packet = struct.pack('!BBH4s', type_igmp, max_resp_time, socket.htons(chksum), group_address)
    return igmp_packet


def prep_igmp_report():
    """
    Připraví IGMP Report packet.
    """
    type_igmp = 0x16                                # Type for IGMP v2 Membership Report
    group_address = socket.inet_aton('224.0.0.5')   # Destination Multicast Address
    igmp_packet = struct.pack('!BBH4s', type_igmp, 0, 0, group_address)
    chksum = checksum(igmp_packet)
    igmp_packet = struct.pack('!BBH4s', type_igmp, 0, socket.htons(chksum), group_address)
    return igmp_packet

def prep_igmp_leave():
    """
    Připraví IGMP Leave Group packet.
    """
    type_igmp = 0x17                                # Type for IGMP Leave Group
    group_address = socket.inet_aton('224.0.0.5')   # Destination Multicast Address
    igmp_packet = struct.pack('!BBH4s', type_igmp, 0, 0, group_address)
    chksum = checksum(igmp_packet)
    igmp_packet = struct.pack('!BBH4s', type_igmp, 0, socket.htons(chksum), group_address)
    return igmp_packet

def send_igmp_packet(packet, destination):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', 1))
    sock.sendto(packet, (destination, 0))


# MLD Packets 
def prep_mld1_query():
    """ 
    Prepaires MLDv2 Query packet
    """
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)  # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLQuery()
    return ip/mld

def prep_mld1_report():
    """ 
    Prepaires MLDv2 Report packet
    """
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)  # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLReport()
    return ip/mld

def prep_mld1_done():
    """
    Prepaires MLDv2 Done packet
    """
    # Create IPv6 Header
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)     # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLDone()                            # Create MLD Done message
    return ip/mld                                   # Assembly packet

def prep_mld2_report():
    """
    Prepaires MLDv2 Report packet
    """
    # Create IPv6 Header
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::16'    # Address for all MLDv2-capable routers
    if not src_address:
        raise ValueError("No IPv6 address found for interface")
    ip = IPv6(src=src_address, dst=dst_address)
    # Create an MLDv2 Report message
    mld = ICMPv6MLReport2()     # Create MLDv2 report message
    mld.mr_type = 143           # MLDv2 report type is 143
    mld.cksum = None            # Auto-calculate checksum
    return ip/mld               # Return Assembled Packet


def prep_ndp_rs():
    """
    Prepaires ICMPv6 Router Solicitation packet
    """
    # The Source Address Associated With the Interface
    src_address = '2001:db8:85a3::1' 
    # Destination Address In Network (Address of All Routers on the Local Link)
    dst_address = 'ff02::2'           
    ip = IPv6(src=src_address, dst=dst_address)
    rs = ICMPv6ND_RS()
    # Mac Address
    lladdr = ICMPv6NDOptSrcLLAddr(lladdr='00:1c:23:12:34:56') 
    return ip/rs/lladdr

def prep_ndp_ns():
    """
    Prepaires ICMPv6 Neighbor Solicitation packet
    """
    # The Source Address Associated With the Interface
    src_address = '2001:db8:85a3::1'
    # Target Address In Network
    target_address = '2001:db8:85a3::2'     
    # Solicited-node Address To Effectively Directed Only to Devices That Have a Portion of the Address 
    # Matching the Last 24 Bits of the Destination Address
    dst_address = "ff02::1:ff00:0002"       
    ip = IPv6(src=src_address, dst=dst_address)
    ns = ICMPv6ND_NS(tgt=target_address)
    lladdr = ICMPv6NDOptSrcLLAddr(lladdr='00:1c:23:12:34:56')
    return ip/ns/lladdr

def prep_ndp_ra():
    """
    Prepaires ICMPv6 Router Advertisement packet
    """
    src_address = '2001:db8:85a3::1'    
    dst_address = 'ff02::1'             # Address of All Routers on the Local Link
    ip = IPv6(src=src_address, dst=dst_address)
    ra = ICMPv6ND_RA()
    lladdr = ICMPv6NDOptSrcLLAddr(lladdr='00:1c:23:12:34:56')
    mtu = ICMPv6NDOptMTU(mtu=1500)
    prefix_info = ICMPv6NDOptPrefixInfo(prefix='2001:db8:85a3::', prefixlen=64, L=1, A=1, validlifetime=86400, preferredlifetime=43200)
    return ip/ra/lladdr/mtu/prefix_info

def prep_ndp_na_broadcast():
    src_address = '2001:db8:1:2::1'  
    dst_address = 'ff02::1'          
    ip = IPv6(src=src_address, dst=dst_address)
    icmp = ICMPv6ND_NA()
    packet = ip/icmp
    return packet

    # Manually Add MAC Address To Neighbor Cache: sudo ip -6 neigh add 2001:db8:85a3::1 lladdr 00:1c:23:12:34:56 dev wlp4s0

def prep_arp_request():
    """
    Připraví ARP Request Packet.
    """
    src_ip = "192.168.1.10"
    dst_ip = "192.168.1.20"
    src_mac = "aa:bb:cc:dd:ee:ff"

    # Ethernet Header: Broadcast MAC as the Destination
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # ARP Header
    arp = ARP(pdst=dst_ip, psrc=src_ip, hwsrc=src_mac, op="who-has")
    return ether / arp

def prep_arp_reply():
    """
    Prepaires ARP Reply Packet.
    """
    src_ip = "192.168.1.20"
    dst_ip = "192.168.1.10"
    src_mac = "ff:ee:dd:cc:bb:aa"
    dst_mac = "aa:bb:cc:dd:ee:ff"

    # Ethernet header
    ether = Ether(dst=dst_mac)
    # ARP header
    arp = ARP(pdst=dst_ip, psrc=src_ip, hwdst=dst_mac, hwsrc=src_mac, op="is-at")
    return ether / arp

def prep_icmp_echo_request():
    """
    Prepaires ICMPv4 Echo Request Packet.
    """
    dst_ip = '192.168.1.1'  
    ip = IP(dst=dst_ip)
    icmp = ICMP(type=8, code=0)                 # Echo Request (Type 8)
    data = 'Hello'                              # Payload
    packet = ip / icmp / data
    return packet

def prep_icmp_echo_reply():
    """
    Prepaires ICMPv4 Echo Reply Packet.
    """
    src_ip = '192.168.1.2'  
    dst_ip = '192.168.1.1'  
    ip = IP(src=src_ip, dst=dst_ip)
    icmp = ICMP(type=0, code=0, id=1, seq=1)    # Echo Reply (Type 0)
    data = 'Reply'                              # Payload
    packet = ip / icmp / data
    return packet