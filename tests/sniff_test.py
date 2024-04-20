import threading
from scapy.all import send, IPv6, ICMPv6MLReport2,ICMPv6MLQuery,ICMPv6MLReport,ICMPv6MLDone
from scapy.all import ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_Redirect, ICMPv6NDOptSrcLLAddr
from scapy.all import ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo,ICMPv6NDOptDstLLAddr
import netifaces as ni # To get the interface IP address
from colorama import init, Fore
import subprocess
import os
import time
import re
import socket
import struct

# Create Virtual Interface For Testing Packets: 
# sudo ip link add name virt0 type dummy
# sudo ip addr add 192.0.2.1/24 dev virt0
# sudo ip link set virt0 up

# Inicialization Colorama
init(autoreset=True)


def get_interface_ipv6_address(interface):
    try:
        ipv6_addr = ni.ifaddresses(interface)[ni.AF_INET6][0]['addr']
        return ipv6_addr
    except (ValueError, KeyError):
        return None



# Funkce pro výpočet kontrolního součtu IGMP
def checksum(msg):
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
    type_igmp = 0x11        # Typ pro IGMP Query
    max_resp_time = 100     # Maximální odpověď v desetinách sekundy
    group_address = socket.inet_aton('0.0.0.0')  # Skupinová adresa (pro general query je to 0.0.0.0)
    igmp_packet = struct.pack('!BBH4s', type_igmp, max_resp_time, 0, group_address)
    chksum = checksum(igmp_packet)
    igmp_packet = struct.pack('!BBH4s', type_igmp, max_resp_time, socket.htons(chksum), group_address)
    return igmp_packet


def prep_igmp_report():
    """
    Připraví IGMP Report packet.
    """
    type_igmp = 0x16  # Typ pro IGMP v2 Membership Report
    group_address = socket.inet_aton('224.0.0.5')  # Cílová multicastová adresa
    igmp_packet = struct.pack('!BBH4s', type_igmp, 0, 0, group_address)
    chksum = checksum(igmp_packet)
    igmp_packet = struct.pack('!BBH4s', type_igmp, 0, socket.htons(chksum), group_address)
    return igmp_packet

def prep_igmp_leave():
    """
    Připraví IGMP Leave Group packet.
    """
    type_igmp = 0x17  # Typ pro IGMP Leave Group
    group_address = socket.inet_aton('224.0.0.5')  # Cílová multicastová adresa
    igmp_packet = struct.pack('!BBH4s', type_igmp, 0, 0, group_address)
    chksum = checksum(igmp_packet)
    igmp_packet = struct.pack('!BBH4s', type_igmp, 0, socket.htons(chksum), group_address)
    return igmp_packet

def send_igmp_packet(packet, destination):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', 1))
    sock.sendto(packet, (destination, 0))


# MLD Packets 
def prep_mld_130():
    """ 
    Prepaires MLDv2 Query packet
    """
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)  # FF02::1 je adresa pro všechny uzly na lokálním segmentu
    mld = ICMPv6MLQuery()
    return ip/mld

def prep_mld_131():
    """ 
    Prepaires MLDv2 Report packet
    """
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)  # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLReport()
    return ip/mld

def prep_mld_132():
    """
    Prepaires MLDv2 Done packet
    """
    # Create IPv6 Header
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)     # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLDone()                            # Create MLD Done message
    return ip/mld                                   # Assembly packet

def prep_mld_143():
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

def send_packet(packet_type):

    if packet_type == 143:
        packet = prep_mld_143()
        send(packet, verbose=False)

    elif packet_type == 130:
        packet = prep_mld_130()
        send(packet, verbose=False)

    elif packet_type == 131:
        packet = prep_mld_131()
        send(packet, verbose=False)

    elif packet_type == 132:
        packet = prep_mld_132()
        send(packet, verbose=False)

    elif packet_type == 'NDP_RS':
        packet = prep_ndp_rs()
        send(packet, verbose=False)

    elif packet_type == 'NDP_NS':
        packet = prep_ndp_ns()
        send(packet, verbose=False)

    elif packet_type == 'NDP_RA':
        packet = prep_ndp_ra()
        send(packet, verbose=False)


    elif packet_type == 'NDP_NA':
        packet = prep_ndp_na_broadcast()
        send(packet, verbose=False)

    elif packet_type == 'IGMP_QUERY':
        packet = prep_igmp_query()
        send_igmp_packet(packet, '224.0.0.1')

    elif packet_type == 'IGMP_REPORT':
        packet = prep_igmp_report()
        send_igmp_packet(packet, '224.0.0.2') 

    elif packet_type == 'IGMP_LEAVE':
        packet = prep_igmp_leave()
        send_igmp_packet(packet, '224.0.0.2') 
    

def run_sniffer(output_queue,packet_type):
    if packet_type in [143,130,131,132]:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--mld"]
    elif packet_type in ['NDP_RS','NDP_NS','NDP_RA','NDP_NA']:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--ndp"]
    elif packet_type in ['IGMP_QUERY','IGMP_REPORT','IGMP_LEAVE']:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--igmp"]

    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            output_queue.put(line)  # Put All Lines of Output in Queue


def check_packet(output,packet_type=143):

    if packet_type == 143:
        expected_src_ip = "2001:db8:85a3::8a2e:370:7334"
        expected_dst_ip = "ff02::16"
        expected_icmpv6_type = "143"

    elif packet_type == 130:
        expected_src_ip = "2001:db8:85a3::8a2e:370:7334"
        expected_dst_ip = "ff02::1"
        expected_icmpv6_type = "130"

    elif packet_type == 131:
        expected_src_ip = "2001:db8:85a3::8a2e:370:7334"
        expected_dst_ip = "ff02::1"
        expected_icmpv6_type = "131"

    elif packet_type == 132:
        expected_src_ip = "2001:db8:85a3::8a2e:370:7334"
        expected_dst_ip = "ff02::1"
        expected_icmpv6_type = "132"

    elif packet_type == 'NDP_RS':
        expected_src_ip = "2001:db8:85a3::1"
        expected_dst_ip = "ff02::2"
        expected_icmpv6_type = "133"  # ICMPv6 type for Router Solicitation
        
    elif packet_type == 'NDP_NS':
        expected_src_ip = "2001:db8:85a3::1"
        expected_dst_ip = "ff02::1:ff00:0002"
        expected_icmpv6_type = "135"  # ICMPv6 type for Neighbor Solicitation

    elif packet_type == 'NDP_RA':
        expected_src_ip = "2001:db8:85a3::1"
        expected_dst_ip = "ff02::1"
        expected_icmpv6_type = "134"  # ICMPv6 type for Router Advertisement

    elif packet_type == 'NDP_NA':
        expected_src_ip = "2001:db8:1:2::1"
        expected_dst_ip = "ff02::1"
        expected_icmpv6_type = "136"  # ICMPv6 type for Neighbor Advertisement

    elif packet_type == 'IGMP_QUERY':
        expected_dst_ip = "224.0.0.1"
        expected_icmpv6_type = "17"
    
    elif packet_type == 'IGMP_REPORT': 
        expected_dst_ip = "224.0.0.2"
        expected_icmpv6_type = "22"

    elif packet_type == 'IGMP_LEAVE':
        expected_dst_ip = "224.0.0.2"
        expected_icmpv6_type = "23"

    # Regex to Capture Necessary Parts of the Packet
    src_ip_match = re.search(r"src IP: (\S+)", output)
    dst_ip_match = re.search(r"dst IP: (\S+)", output)
    icmpv6_type_match = re.search(r"ICMPv6 type: (\d+)", output)

    if src_ip_match and dst_ip_match and icmpv6_type_match:
        src_ip = src_ip_match.group(1)
        dst_ip = dst_ip_match.group(1)
        icmpv6_type = icmpv6_type_match.group(1)

        # Compare Against Expected Values
        if (packet_type in [143, 130, 131, 132] and src_ip == expected_src_ip and dst_ip == expected_dst_ip and
            icmpv6_type == expected_icmpv6_type):
            print(f"Packet Fully Matched {packet_type}")
            return True
        
        elif (packet_type in ['NDP_RS','NDP_NS','NDP_RA','NDP_NA'] and icmpv6_type in ['133','135','134','136','137']):
            
            if icmpv6_type == expected_icmpv6_type:
                print(f"Packet Fully Matched {packet_type}")
            else:
                print(f"Packet Not Matched (Catched: {icmpv6_type})")
            return True
    else:
        dst_ip_match = re.search(r"dst IP: (\S+)", output)
        icmpv4 = re.search(r"IGMP type: (\d+)", output)

        if (packet_type in ['IGMP_QUERY','IGMP_REPORT','IGMP_LEAVE'] and dst_ip_match and icmpv4):
            dst_ip = dst_ip_match.group(1)
            icmpv4_type = icmpv4.group(1)
            if dst_ip == expected_dst_ip and icmpv4_type == expected_icmpv6_type:
                print(f"Packet Fully Matched {packet_type}")
            else:
                print(output)
            return True
        else:
            print(output)

    return False


if __name__ == "__main__":
    from queue import Queue
    packet_types = [143, 130, 131, 132,'NDP_RS','NDP_NS','NDP_RA','NDP_NA','IGMP_QUERY','IGMP_REPORT','IGMP_LEAVE']
    interface = 'wlp4s0'
    test_idx = 1


    for mld_type in packet_types:
        output_queue = Queue() 
        sniffer_thread = threading.Thread(target=run_sniffer, args=(output_queue,mld_type ))
        sniffer_thread.start()
        time.sleep(1) 

        send_packet(mld_type)
        sniffer_thread.join(timeout=2)
        output = "".join(list(output_queue.queue))

        if check_packet(output, mld_type):
            print(Fore.GREEN + f"TEST: {test_idx} [type {mld_type} packet] captured and verified.")
        else:
            print(Fore.RED + f"TEST: {test_idx} [type {mld_type} packet] Failed to verify.")
            print("Output is: ")
            print(output)
        test_idx += 1  

# sudo ip -6 addr add 2001:db8:85a3::1/64 dev virt0