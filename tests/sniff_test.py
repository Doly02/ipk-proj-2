import threading
from scapy.all import send, IPv6, ICMPv6MLReport2,ICMPv6MLQuery,ICMPv6MLReport,ICMPv6MLDone
from scapy.all import ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_Redirect, ICMPv6NDOptSrcLLAddr
import netifaces as ni # To get the interface IP address
from colorama import init, Fore
import subprocess
import os
import time
import re

MLD = 1
NDP = 2

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


# MLD Packets 
def send_mld_130():
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)  # FF02::1 je adresa pro všechny uzly na lokálním segmentu
    mld = ICMPv6MLQuery()
    return ip/mld

def send_mld_131():
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)  # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLReport()
    return ip/mld

def send_mld_132():
    # Create IPv6 Header
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)  # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLDone() # Create MLD Done message
    return ip/mld # Assembly packet

def send_mld_143():
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


def send_ndp_rs():
    # The Source Address Associated With the Interface
    src_address = '2001:db8:85a3::1' 
    # Destination Address In Network (Address of All Routers on the Local Link)
    dst_address = 'ff02::2'           
    ip = IPv6(src=src_address, dst=dst_address)
    rs = ICMPv6ND_RS()
    # Mac Address
    lladdr = ICMPv6NDOptSrcLLAddr(lladdr='00:1c:23:12:34:56') 
    return ip/rs/lladdr

def send_ndp_ns():
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





def send_packet(packet_type):

    if packet_type == 143:
        packet = send_mld_143()
        send(packet,verbose=False)  # Send packet
    
    elif packet_type == 130:
        packet = send_mld_130()
        send(packet,verbose=False)  # Send packet

    elif packet_type == 131:
        packet = send_mld_131()
        send(packet,verbose=False)  # Send packet

    elif packet_type == 132:
        packet = send_mld_132()
        send(packet,verbose=False)  # Send packet

    elif packet_type == 'NDP_RS':
        packet = send_ndp_rs()
        send(packet,verbose=False)  # Send packet

    elif packet_type == 'NDP_NS':
        packet = send_ndp_ns()
        send(packet,verbose=False)  # Send packet

def run_sniffer(output_queue,packet_type):
    if packet_type in [143,130,131,132]:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--mld"]
    elif packet_type in ['NDP_RS','NDP_NS']:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--ndp"]

    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            output_queue.put(line)  # Put every line of output in queue


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


    # Regex to capture necessary parts of the packet
    src_ip_match = re.search(r"src IP: (\S+)", output)
    dst_ip_match = re.search(r"dst IP: (\S+)", output)
    icmpv6_type_match = re.search(r"ICMPv6 type: (\d+)", output)

    if src_ip_match and dst_ip_match and icmpv6_type_match:
        src_ip = src_ip_match.group(1)
        dst_ip = dst_ip_match.group(1)
        icmpv6_type = icmpv6_type_match.group(1)

        # Compare against expected values
        if (packet_type in [143, 130, 131, 132] and src_ip == expected_src_ip and dst_ip == expected_dst_ip and
            icmpv6_type == expected_icmpv6_type):
            return True
        elif (packet_type in ['NDP_RS','NDP_NS'] and icmpv6_type in ['133','135','134','136','137']):
            return True
    return False


if __name__ == "__main__":
    from queue import Queue
    packet_types = [143, 130, 131, 132,'NDP_RS','NDP_NS']
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