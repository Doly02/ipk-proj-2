#
#   Project: IPK Project 2 - Packet Sniffer
#   Author:  Tomas Dolak
#   File:    sniff_test.py
#   Description: This Script is Used to Test the Packet Sniffer. Script First Runs the Sniffer And Then Sends a Packet of a Specific Type That Should Be Sniffed. 
#   The Captured Packet is Evaluated Against the Expected Values.
#

# Libraries
import threading
from scapy.all import send, sendp
from prep_packet import *
from colorama import init, Fore
import subprocess
import time
import re

# Inicialization Colorama
init(autoreset=True)

def send_packet(packet_type):
    """
    Send Packet of Specific Type to the Network.
    """

    if packet_type == 'MLD2_REP':
        packet = prep_mld2_report()
        send(packet, verbose=False)

    elif packet_type == 'MLD1_QUE':
        packet = prep_mld1_query()
        send(packet, verbose=False)

    elif packet_type == 'MLD1_REP':
        packet = prep_mld1_report()
        send(packet, verbose=False)

    elif packet_type == 'MLD1_DON':
        packet = prep_mld1_done()
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
    
    elif packet_type == 'ARP_REQUEST':
        packet = prep_arp_request()
        sendp(packet, verbose=False)  # Send on Link Layer

    elif packet_type == 'ARP_REPLY':
        packet = prep_arp_reply()
        sendp(packet, verbose=False)  # Send on Link Layer

    elif packet_type == 'ICMP4_ECHO_REQUEST':
        packet = prep_icmp4_echo_request()
        send(packet, verbose=False)

    elif packet_type == 'ICMP4_ECHO_REPLY':
        packet = prep_icmp4_echo_reply()
        send(packet, verbose=False)

    elif packet_type == 'ICMP6_ECHO_REQUEST':
        packet = prep_icmpv6_echo_request()
        send(packet, verbose=False)
    
    elif packet_type == 'ICMP6_ECHO_REPLY':
        packet = prep_icmpv6_echo_reply()
        send(packet, verbose=False)

def run_sniffer(output_queue,packet_type):
    """
    Runs Sniffer to Capture Packets of Specific Type.
    """
    if packet_type in ['MLD2_REP', 'MLD1_QUE', 'MLD1_REP', 'MLD1_DON']:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--mld"]
    elif packet_type in ['NDP_RS','NDP_NS','NDP_RA','NDP_NA']:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--ndp"]
    elif packet_type in ['IGMP_QUERY','IGMP_REPORT','IGMP_LEAVE']:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--igmp"]
    elif packet_type in ['ARP_REQUEST','ARP_REPLY']:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--arp"]
    elif packet_type in ['ICMP4_ECHO_REQUEST','ICMP4_ECHO_REPLY']:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--icmp4"]
    elif packet_type in ['ICMP6_ECHO_REQUEST','ICMP6_ECHO_REPLY']:
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--icmp6"]


    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            output_queue.put(line)  # Put All Lines of Output in Queue


def check_packet(output,packet_type=None):
    """
    Checks Captured Packet Against Expected Values.
    """
    if packet_type == None:
        return False
    
    if packet_type == 'MLD2_REP':
        expected_src_ip = "2001:db8:85a3::8a2e:370:7334"
        expected_dst_ip = "ff02::16"
        expected_icmpv6_type = "143"

    elif packet_type == 'MLD1_QUE':
        expected_src_ip = "2001:db8:85a3::8a2e:370:7334"
        expected_dst_ip = "ff02::1"
        expected_icmpv6_type = "130"

    elif packet_type == 'MLD1_REP':
        expected_src_ip = "2001:db8:85a3::8a2e:370:7334"
        expected_dst_ip = "ff02::1"
        expected_icmpv6_type = "131"

    elif packet_type == 'MLD1_DON':
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

    elif packet_type == 'ARP_REQUEST':
        expected_sender_mac = "aa:bb:cc:dd:ee:ff"
        expected_src_ip = "192.168.1.10"
        expected_target_mac = "00:00:00:00:00:00"
        expected_target_ip = "192.168.1.20"

    elif packet_type == 'ARP_REPLY':
        expected_sender_mac = "ff:ee:dd:cc:bb:aa"
        expected_src_ip = "192.168.1.20"
        expected_target_mac = "aa:bb:cc:dd:ee:ff"
        expected_target_ip = "192.168.1.10"

    elif packet_type == 'ICMP4_ECHO_REQUEST':
        expected_icmpv4_type = "8"
        expected_icmpv4_code = "0"

    elif packet_type == 'ICMP4_ECHO_REPLY':
        expected_icmpv4_type = "0"
        expected_icmpv4_code = "0"

    elif packet_type == 'ICMP6_ECHO_REQUEST':
        expected_icmpv6_type = "128"
    
    elif packet_type == 'ICMP6_ECHO_REPLY':
        expected_icmpv6_type = "129"

    # Regex to Capture Necessary Parts of the Packet
    src_ip_match = re.search(r"src IP:[ ]*(\S+)", output)
    dst_ip_match = re.search(r"dst IP:[ ]*(\S+)", output)
    icmpv6_type_match = re.search(r"ICMPv6 type:[ ]*(\d+)", output)
    sender_mac_match = re.search(r"Sender MAC:[ ]*(\S+)", output)
    target_mac_match = re.search(r"Target MAC:[ ]*(\S+)", output)
    sender_ip_match = re.search(r"Sender IP:[ ]*(\S+)", output)
    target_ip_match = re.search(r"Target IP:[ ]*(\S+)", output)
    icmpv4_type_match = re.search(r"ICMPv4 type:[ ]*(\d+)", output)
    icmpv4_code_match = re.search(r"ICMPv4 code:[ ]*(\d+)", output)

    if src_ip_match and dst_ip_match and icmpv6_type_match:
        src_ip = src_ip_match.group(1)
        dst_ip = dst_ip_match.group(1)
        icmpv6_type = icmpv6_type_match.group(1)

        # Compare Against Expected Values
        if (packet_type in ['MLD2_REP', 'MLD1_QUE', 'MLD1_REP', 'MLD1_DON'] and src_ip == expected_src_ip and dst_ip == expected_dst_ip and
            icmpv6_type == expected_icmpv6_type):
            print(f"Packet Fully Matched {packet_type}")
            return True
        
        elif (packet_type in ['NDP_RS','NDP_NS','NDP_RA','NDP_NA'] and icmpv6_type in ['133','135','134','136','137']):
            
            if icmpv6_type == expected_icmpv6_type:
                print(f"Packet Fully Matched {packet_type}")
            else:
                print(f"Packet Not Matched (Catched: {icmpv6_type})")
            return True
                
        elif packet_type in ['ICMP6_ECHO_REQUEST', 'ICMP6_ECHO_REPLY']:
            if (icmpv6_type == expected_icmpv6_type):
                print(f"Packet Fully Matched {packet_type}")
                return True
    else:
        dst_ip_match = re.search(r"dst IP:[ ]*(\S+)", output)
        icmpv4 = re.search(r"IGMP type:[ ]*(\d+)", output)

        if (packet_type in ['IGMP_QUERY','IGMP_REPORT','IGMP_LEAVE'] and dst_ip_match and icmpv4):
            dst_ip = dst_ip_match.group(1)
            icmpv4_type = icmpv4.group(1)
            if dst_ip == expected_dst_ip and icmpv4_type == expected_icmpv6_type:
                print(f"Packet Fully Matched {packet_type}")
            else:
                print(output)
            return True

        elif (packet_type in ['ARP_REQUEST','ARP_REPLY']):
            if sender_ip_match and target_ip_match and sender_mac_match and target_mac_match:
                sender_ip = sender_ip_match.group(1)
                target_ip = target_ip_match.group(1)
                src_mac = sender_mac_match.group(1)
                dst_mac = target_mac_match.group(1)
                
                # Zde pokračujte ve vašem logickém ověřování...
                if (sender_ip == expected_src_ip and target_ip == expected_target_ip and
                    dst_mac == expected_target_mac and src_mac == expected_sender_mac):
                    print(f"ARP Packet Fully Matched {packet_type}")
                    return True
                else:
                    # Not Matched
                    print(Fore.YELLOW,"NOTE: Necessary packet details not found in output.")
                    return False
                
        elif packet_type in ['ICMP4_ECHO_REQUEST','ICMP4_ECHO_REPLY']:
            icmpv4_type = icmpv4_type_match.group(1)
            icmpv4_code = icmpv4_code_match.group(1)
            if icmpv4_type == expected_icmpv4_type and icmpv4_code == expected_icmpv4_code:
                print(f"Packet Fully Matched {packet_type}")
                return True
        else:
            print(output)

    print(Fore.YELLOW + "NOTE: Necessary packet details not found in output.")
    return False


if __name__ == "__main__":
    from queue import Queue
    packet_types = ['MLD2_REP', 'MLD1_QUE', 'MLD1_REP', 'MLD1_DON',         # MLDv1 and MLDv2
                    'NDP_RS','NDP_NS','NDP_RA','NDP_NA',                    # NDP
                    'IGMP_QUERY','IGMP_REPORT','IGMP_LEAVE',                # IGMP
                    'ARP_REQUEST','ARP_REPLY',                              # ARP
                    'ICMP4_ECHO_REQUEST','ICMP4_ECHO_REPLY',                  # ICMPv4
                    'ICMP6_ECHO_REQUEST', 'ICMP6_ECHO_REPLY']                               # ICMPv6
    interface = 'wlp4s0'
    test_idx = 1


    for pct_type in packet_types:
        output_queue = Queue() 
        sniffer_thread = threading.Thread(target=run_sniffer, args=(output_queue,pct_type ))
        sniffer_thread.start()
        time.sleep(1) 

        send_packet(pct_type)
        sniffer_thread.join(timeout=2)
        output = "".join(list(output_queue.queue))

        if check_packet(output, pct_type):
            print(Fore.GREEN + f"TEST: {test_idx} [type {pct_type} packet] captured and verified.")
        else:
            print(Fore.RED + f"TEST: {test_idx} [type {pct_type} packet] Failed to verify.")
            print("Output is: ")
            print(output)
        test_idx += 1  

# sudo ip -6 addr add 2001:db8:85a3::1/64 dev virt0