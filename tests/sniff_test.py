#
#   File:        sniff_test.py
#   Author:      Tomas Dolak
#   Description: Test Script To Verify Sniffing Of MLD Packets. In One Thread, Sends MLD Packets, In Another Thread, Sniffs For MLD Packets.
#                Then The Sniffer Output Is Checked Against Expected Values.
#


import threading
from scapy.all import send, IPv6, ICMPv6MLReport2,ICMPv6MLQuery,ICMPv6MLReport,ICMPv6MLDone
from scapy.all import ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_Redirect, ICMPv6NDOptSrcLLAddr
import subprocess
import os
import time
import re


# MLD Packets
def send_mld_130():
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)     # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLQuery()
    return ip/mld

def send_mld_131():
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)     # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLReport()
    return ip/mld

def send_mld_132():
    # Create IPv6 Header
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::1'  
    ip = IPv6(src=src_address, dst=dst_address)     # FF02::1 Address For All Nodes On Local Segment
    mld = ICMPv6MLDone()                            # Create MLD Done message
    return ip/mld                                   # Assembly packet

def send_mld_143():
    # Create IPv6 Header
    src_address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
    dst_address = 'FF02::16'    # Address for all MLDv2-capable routers

    ip = IPv6(src=src_address, dst=dst_address)
    # Create an MLDv2 Report message
    mld = ICMPv6MLReport2()     # Create MLDv2 report message
    mld.mr_type = 143           # MLDv2 report type is 143
    mld.cksum = None            # Auto-calculate checksum
    return ip/mld               # Return Assembled Packet



def send_mld_packet(packet_type):


    if packet_type == 143:
        packet = send_mld_143()

    elif packet_type == 130:
        packet = send_mld_130()

    elif packet_type == 131:
        packet = send_mld_131()
    
    elif packet_type == 132:
        packet = send_mld_132()


    # Send the packet
    send(packet,verbose=False)

def run_sniffer(output_queue):
    command = [".././ipk-sniffer", "-i", "wlp4s0", "--mld"]
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            output_queue.put(line)  # Put Every line of Output in The Queue


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

    #print(output)

    # Regex to Capture Necessary Parts of The Packet
    src_ip_match = re.search(r"src IP: (\S+)", output)
    dst_ip_match = re.search(r"dst IP: (\S+)", output)
    icmpv6_type_match = re.search(r"ICMPv6 type: (\d+)", output)

    if src_ip_match and dst_ip_match and icmpv6_type_match:
        src_ip = src_ip_match.group(1)
        dst_ip = dst_ip_match.group(1)
        icmpv6_type = icmpv6_type_match.group(1)

        # Compare against expected values
        if (src_ip == expected_src_ip and
            dst_ip == expected_dst_ip and
            icmpv6_type == expected_icmpv6_type):
            return True
    return False


if __name__ == "__main__":
    from queue import Queue
    mld_types = [143, 130, 131, 132]

    for mld_type in mld_types:
        output_queue = Queue()  
        sniffer_thread = threading.Thread(target=run_sniffer, args=(output_queue,))
        sniffer_thread.start()
        time.sleep(2) 

        send_mld_packet(mld_type)
        sniffer_thread.join(timeout=11)
        output = "".join(list(output_queue.queue))

        if check_packet(output, mld_type):
            print(f"MLD type {mld_type} packet captured and verified.")
        else:
            print(f"Failed to verify MLD type {mld_type} packet.")
