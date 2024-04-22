#
#   Project: IPK Project 2 - Packet Sniffer
#   Author:  Tomas Dolak
#   File:    advanced_tests.py
#   Description: This Script is Used to Test the Packet Sniffer. Script First Runs the Sniffer And Then Sends a Packet of a Specific Type That Should Be Sniffed. 
#   The Captured Packet is Evaluated Against the Expected Values.
#

# Libraries
import threading
from scapy.all import send, sendp
from prep_packet import *
from prep_packet import *
from colorama import init, Fore
from scapy.all import IP, TCP, UDP, Ether, sendp
import subprocess
import time
import re

init(autoreset=True)

def send_packet(packet_type, iface='wlp4s0'):
    if packet_type == 'TCP_GENERIC_N_10':
        packet = prep_tcp()
        sendp(packet, iface=iface, verbose=False)
    elif packet_type == 'UDP_GENERIC_N_25':
        packet = prep_udp()
        sendp(packet, iface=iface, verbose=False)  # Send 40 Packets Instead of 25 To Ensure That 25 Packet Are Absolutely Send 
    elif packet_type == 'MLD_TCP_N_20':
        packet = prep_mld1_done()
        send(packet,verbose=False)
        

def run_sniffer(output_queue,packet_type,n):
    n_str = str(n)
    if packet_type == 'TCP_GENERIC_N_10':
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--tcp","-n",n_str]
    elif packet_type == 'UDP_GENERIC_N_25':
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--udp", "-n", n_str]
    elif packet_type == 'MLD_TCP_N_20':
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--tcp", "--mld", "-n", n_str]

    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            output_queue.put(line)  # Put All Lines of Output in Queue

def check_packet(output, num_ex_packets,packet_type):
    """
    Checks If Sniffed Packets Are Expected.
    """
    if packet_type == 'TCP_GENERIC_N_10' or packet_type == 'MLD_TCP_N_20':
        pattern = r"Acknowledgment Number:"
        pattern_mld = r"MLD"
    elif packet_type == 'UDP_GENERIC_N_25':
        pattern = r'UDP Length:'
    
    if packet_type == 'TCP_GENERIC_N_10' or packet_type == 'UDP_GENERIC_N_25':
        matches = re.findall(pattern, output)
        if len(matches) == num_ex_packets:
            return True
        print(Fore.YELLOW + f"In test {packet_type} Found: {len(matches)}")
        return False
    elif packet_type == 'MLD_TCP_N_20':
        matches_tcp = re.findall(pattern, output)
        matches_mld = re.findall(pattern_mld, output)
        sum = len(matches_tcp) + len(matches_mld)
        if sum == num_ex_packets:
            return True
        print(Fore.YELLOW + f"In test {packet_type} Found: {len(matches)}")
        return False

def advanced_tests():
    print(Fore.LIGHTMAGENTA_EX + "Starting: Advanced Testing")
    from queue import Queue
    packet_types = ['TCP_GENERIC_N_10','UDP_GENERIC_N_25','MLD_TCP_N_20']  # Extend with other packet types as needed
    interface = 'wlp4s0'
    test_idx = 1
    num_tcp_10 = 10
    num_udp_25 = 25
    num_mld_10 = 10
        

    for pct_type in packet_types:
        output_queue = Queue()
        num1 = 0
        num2 = 0
        sum = 0
        if pct_type == 'TCP_GENERIC_N_10' or 'MLD_TCP_N_20':
            num1 = num_tcp_10
        elif pct_type == 'UDP_GENERIC_N_25':
            num1 = num_udp_25
        
        if pct_type == 'MLD_TCP_N_20':
            num2 = num_mld_10

        sum = num1 + num2
            
        sniffer_thread = threading.Thread(target=run_sniffer, args=(output_queue,pct_type,sum ))
        sniffer_thread.start()

        for _ in range(num1):
            send_packet(pct_type, interface)
            time.sleep(0.1)
            
        for _ in range(num2):
            send_packet(pct_type,interface)
            
        sniffer_thread.join(timeout=10)
        output = "".join(list(output_queue.queue))

        if check_packet(output, sum, pct_type):
            print(f"Packets Fully Matched {pct_type}")
            print(Fore.GREEN + f"TEST: {test_idx} [type {pct_type}] captured and verified.")
        else:
            print(Fore.RED + f"TEST: {test_idx} [type {pct_type}] Failed to verify.")
            print(output)
        test_idx += 1  