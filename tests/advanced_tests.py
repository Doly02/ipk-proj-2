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


def run_sniffer(output_queue,packet_type,n):
    n_str = str(n)
    if packet_type == 'TCP_GENERIC_N_10':
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--tcp","-n",n_str]
    elif packet_type == 'UDP_GENERIC_N_25':
        command = [".././ipk-sniffer", "-i", "wlp4s0", "--udp", "-n", n_str]

    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            output_queue.put(line)  # Put All Lines of Output in Queue

def check_packet(output, num,packet_type):
    """
    Kontroluje, zda byl vzor zachycen 10x výstupem.
    """
    if packet_type == 'TCP_GENERIC_N_10':
        pattern = r"Acknowledgment Number:"
    elif packet_type == 'UDP_GENERIC_N_25':
        pattern = r'UDP Length:'
        
    matches = re.findall(pattern, output)
    if len(matches) == num:
        return True
    print(Fore.YELLOW + f"In test {packet_type} Found: {len(matches)}")
    return False

if __name__ == "__main__":
    print(Fore.LIGHTMAGENTA_EX + "Starting: Advanced Testing")
    from queue import Queue
    packet_types = ['TCP_GENERIC_N_10','UDP_GENERIC_N_25']  # Extend with other packet types as needed
    interface = 'wlp4s0'
    test_idx = 1
    num_tcp_10 = 10
    num_udp_25 = 25

        

    for pct_type in packet_types:
        output_queue = Queue()
         
        if pct_type == 'TCP_GENERIC_N_10':
            num = num_tcp_10
        elif pct_type == 'UDP_GENERIC_N_25':
            num = num_udp_25
            
        sniffer_thread = threading.Thread(target=run_sniffer, args=(output_queue,pct_type,num ))
        sniffer_thread.start()

        for _ in range(num):
            send_packet(pct_type, interface)
            time.sleep(0.1)
            
        sniffer_thread.join(timeout=10)
        output = "".join(list(output_queue.queue))

        if check_packet(output, num, pct_type):
            print(Fore.GREEN + f"TEST: {test_idx} [type {pct_type}] captured and verified.")
        else:
            print(Fore.RED + f"TEST: {test_idx} [type {pct_type}] Failed to verify.")
            print(output)
        test_idx += 1  