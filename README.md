# IPK Project 2: IPK Network sniffer
- Author: Tomáš Dolák 
- Login: [xdolak09](https://www.vut.cz/lide/tomas-dolak-247220)
- Email: <xdolak09@stud.fit.vutbr.cz>


The goal of this second project in the subject of communication and site was to create a network sniffer. The assignment can be viewed [here](https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%202/zeta).

## Table of contents
- [Requirements](#requirements)
- [Installation](#installation)
- [Project organization](#project-organization)
- [Required theory](#required-theory)
    - [Packets](#packets)
- [Resources](#resources)


## Requirements
To build and run `ipk-sniffer`, you will need the following:

### Compiler
- **Clang++** with support for **C++17** standard. This project uses specific compiler flags to enforce code quality and standards. Make sure your compiler version supports `-std=c++17` along with the flags `-Wall -Wextra -Werror -Wshadow -Wnon-virtual-dtor -pedantic`.

### Libraries
- **Google Test (gtest)**: Required for compiling and running the unit tests. Ensure you have Google Test installed on your system as it uses `-lgtest -lgtest_main -pthread` flags for linking.

- **python scapy**: Scapy is a packet manipulation tool for computer networks. Library is required for run `python3` script which checks that all packet subsets that need to be captured are captured by the sniffer.

The `Scapy` Library can be installed on Ubuntu by command:
`pip install scapy`

### Build tools
- **Make**: This project uses a `Makefile` for easy building and testing. Ensure you have Make installed on your system.

### Operating system
- The Makefile and C++ code were designed with Unix-like environments in mind (Linux, MacOS). While it may be possible to compile and run the project on Windows, using a Unix-like environment (or WSL for Windows users) is recommended.

## Installation
1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. Run `make` to build the client application. This will create the `ipk24chat-client` executable.
4. (Optional) Run `make test` to build and run the unit tests. Ensure you have Google Test installed.

Please refer to the Makefile for additional targets and commands.

## Project organization 
```
ipk-proj-1/
│
├── include/                # Header files for class declarations.
│
├── src/                    # Source files containing class definitions and main application logic.
│
├── test/                   # Test files
│   ├── mld_test/           # Python scripts based on scapy library, used to send MLD packets.
│   │   
│   │── prep_packet.py      # Script with functions that prepare packets to be forwarded.
│   │   
│   └── sniff_test.py       # The main test script, turns on the sniffer, sends the packet and checks the output.
│
├── doc/                    # Documentation files and resources
│   └── pics/               # Directory of pictures used in README.md
│
├── Makefile                # Makefile for compiling the project
│
└── README.md               # Overview and documentation for the project
```

## Required theory
In order to use the program correctly and to understand its output, it is necessary to have a certain base of knowledge in your head, which is described in this chapter.
The chapter also contains examples of the program.

### Packets  
In networking, a packet is a small segment of data divided from a larger message, suitable for transmission over computer networks like the Internet. This method allows for the reassembly of the original message by the receiving device. Using packets enables the internet to function as a packet-switching network, where data can be sent in small pieces that travel independently over various paths. [1]

Each packet includes a header and a payload. The header provides essential information such as the packet's origin, destination, and sequence, which helps the receiving device process and reorder the packets correctly. Beyond headers, packets can also have trailers or footers, added by specific network protocols, that contain additional data about the packet.[2]

### Sniffed packet types

#### Why we use packets?
In Network do not use just one packet type but use multiple packet types to accommodate different types of data and optimize network performance. By using multiple packet types, the network can tailor packet handling and processing specifically to the needs of different types of data.[3]

Another reason for using multiple packet types is to support various communication patterns, such as TCP vs UDP, single flow vs multiple flows, and different container networking technologies, such as those found in Windows and Linux. Futhermore security is also one of the reasons for using multiple packet types. Using multiple packet types in a network offers several benefits.

#### Transmission Control Protocol (TCP)
Transmission Control Protocol (TCP) is a foundational technology for the Internet, characterized as a connection-oriented protocol. It facilitates reliable data transmission between devices and applications across networks by ensuring data delivery is verified. TCP is preferred for its reliability in ensuring complete and accurate data transfer. However, this reliability comes with higher bandwidth consumption due to its extensive feedback and error-handling mechanisms.[4]

TCP is used for loading web pages via HTTP (Hypertext Transfer Protocol) and HTTPS (HTTP Secure). Protocols such as SMTP (Simple Mail Transfer Protocol) for sending emails, POP (Post Office Protocol) and IMAP (Internet Message Access Protocol) for retrieving emails, rely on TCP to ensure messages are sent and received without errors. Also another protocols like FTP (File Transfer Protocol), SFTP (SSH File Transfer Protocol), SLL (Secure Sockets Layer), etc.

#### User Datagram Protocol (UDP)
User Datagram Protocol (UDP) is a communication protocol that facilitates the transmission of data across networks without establishing a connection or verifying the delivery of data. It is often referred to as a "connectionless" or "fire-and-forget" protocol because it sends data without ensuring that it reaches the recipient. This trait makes UDP particularly suitable for real-time applications where speed is more critical than reliability.[4]


#### Internet Control Message Protocol (ICMP)
The Internet Control Message Protocol (ICMP) is a network layer protocol that plays a crucial role in diagnosing and reporting network communication issues. It is widely used by network devices like routers to ensure data is reaching its intended destination efficiently and to handle errors in network communications. ICMP does not establish a connection before sending messages.[5]



**Note** Sniffer is able to sniff ICMPv4 and ICMPv6 packet.

#### Internet Group Management Protocol (IGMP)
The Internet Group Management Protocol (IGMP) is a network layer protocol used primarily in IPv4 networks to facilitate the management of multicast groups. IGMP allows multiple devices to share a single IP address designated for multicasting, enabling them to receive the same data simultaneously. IGMP operates by allowing devices on a network to communicate their interest in joining or leaving multicast groups. Routers supporting IGMP listen to these transmissions to maintain a record of which devices are members of specific multicast groups. Multicast IP addresses, which range from 224.0.0.0 to 239.255.255.255, are used exclusively for these groups. When data is sent to a multicast group, the router replicates the packets and distributes them to all members of the group.[6]

#### Address Resolution Protocol (ARP)
The Address Resolution Protocol (ARP) is a fundamental protocol used in local area networks (LANs) to associate the dynamic Internet Protocol (IP) addresses with the fixed physical machine addresses, or Media Access Control (MAC) addresses. This association is essential because IP addresses (used in the network layer) and MAC addresses (used in the data link layer) differ in format and function. ARP operates by translating the 32-bit IP address (commonly IPv4) into a 48-bit MAC address and vice versa, allowing devices on a network to identify and communicate with each other effectively. When a device on a LAN needs to communicate with another device, it uses ARP to find the MAC address associated with the intended IP address.[7]

#### Neighbor Discovery Protocol (NDP)
The Neighbor Discovery Protocol (NDP) is a crucial protocol used with IPv6, functioning at Layer 2 (Data Link Layer) of the OSI model. NDP performs several key tasks essential for efficient and consistent data transmission across IPv6 networks. These tasks include stateless address autoconfiguration, address resolution, Neighbor Unreachability Detection (NUD), and Duplicate Address Detection (DAD). NDP replaces the Address Resolution Protocol (ARP) used in IPv4, adapting these functions to the IPv6 environment.[8]

#### Multicast Listener Discovery Protocol (MLD)
IPv6 Multicast Listener Discovery (MLD) is a protocol used by IPv6 devices to identify and manage the presence of multicast listeners on a network. These listeners are nodes interested in receiving multicast packets addressed to specific multicast groups. MLD is integral to the efficient operation of IPv6 multicast routing and is implemented in two versions: MLD version 1 and MLD version 2, based on IGMP versions for IPv4. MLDv1 corresponds to IGMPv2 for IPv4 and is used for basic multicast listener functions. MLDv2 is based on IGMPv3, that supports more advanced features such as source filtering, allowing nodes to specify which sources they are interested in receiving multicast data from.[9]




## Resources 
[1] "What is a packet? | Network packet definition" [online]. [cited 2024-04-21]. Available at [https://www.cloudflare.com/learning/network-layer/what-is-a-packet/](https://www.cloudflare.com/learning/network-layer/what-is-a-packet/)

[2] Teerawat Issariyakul, Ekram Hossain: *Introduction to Network Simulator NS2*. Chapter: Packets, Packet Headers, and Header Format (pages 169-208). 2012. ISBN: 9780387717609, 0387717609. [cited 2024-04-21].

[3] Nteziriza Nkerabahizi Josbert, Wang Ping, Min Wei, Mohammed Saleh Ali Muthanna and Ahsan Rafiq: "A Framework for Managing Dynamic Routing in Industrial Networks Driven by Software-Defined Networking Technology" in IEEE Access, vol. 9 [online]. May 2021.  ISSN: 2169-3536. DOI: 10.1109/ACCESS.2021.3079896. [cited 2024-04-21]. Avalaible at [https://ieeexplore.ieee.org/document/9430558](https://ieeexplore.ieee.org/document/9430558)

[4] Chiradeep BasuMallick: "TCP vs. UDP: Understanding 10 Key Differences" [online]. April 2022. [cited 2024-04-21]. Available at [https://www.spiceworks.com/tech/networking/articles/tcp-vs-udp/](https://www.spiceworks.com/tech/networking/articles/tcp-vs-udp/)

[5] "What is the Internet Control Message Protocol (ICMP)?"  [online]. [cited 2024-04-21]. Available at [https://www.cloudflare.com/learning/ddos/glossary/internet-control-message-protocol-icmp/](https://www.cloudflare.com/learning/ddos/glossary/internet-control-message-protocol-icmp/)

[6] "What is IGMP? | Internet Group Management Protocol" [online]. [cited 2024-04-21]. Available at [https://www.cloudflare.com/learning/network-layer/what-is-igmp/](https://www.cloudflare.com/learning/network-layer/what-is-igmp/) 

[7]"What Is Address Resolution Protocol (ARP)?". [cited 2024-04-21]. Available at [https://www.fortinet.com/resources/cyberglossary/what-is-arp](https://www.fortinet.com/resources/cyberglossary/what-is-arp)

[8] "Neighbor Discovery Protocol – NDP Overview" [online]. [cited 2024-04-21]. Available at [https://study-ccna.com/ndp-neighbor-discovery-protocol/](https://study-ccna.com/ndp-neighbor-discovery-protocol/)

[9] "IP Multicast Configuration Guide, Cisco IOS XE 17.x" [online]. Chapter: IPv6 Multicast Listener Discovery Protocol. March 2022. [cited 2024-04-21]. Available at [https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-multicast/b-ip-multicast/m_ipv6-mcast-mld-xe.html](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-multicast/b-ip-multicast/m_ipv6-mcast-mld-xe.html)