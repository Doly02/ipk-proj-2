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
    - [Why we use packets?](#why-we-use-packets)
    - [Transmission Control Protocol (TCP)](#transmission-control-protocol-tcp)
    - [User Datagram Protocol (UDP)](#user-datagram-protocol-udp)
    - [Internet Control Message Protocol (ICMP)](#internet-control-message-protocol-icmp)
    - [Internet Group Management Protocol (IGMP)](#internet-group-management-protocol-igmp)
    - [Address Resolution Protocol (ARP)](#address-resolution-protocol-arp)
    - [Neighbor Discovery Protocol (NDP)](#neighbor-discovery-protocol-ndp)
    - [Multicast Listener Discovery Protocol (MLD)](#multicast-listener-discovery-protocol-mld)
- [Testing](#testing)
    - [Manual Testing](#manual-testing)
    - [Automated Testing](#automated-testing)
    - [Wireshark](#wireshark)
- [Resources](#resources)

## Requirements
To build and run `ipk-sniffer`, you will need the following:

### Compiler
- **Clang++** with support for **C++17** standard. This project uses specific compiler flags to enforce code quality and standards. Make sure your compiler version supports `-std=c++17` along with the flags `-Wall -Wextra -Werror -Wshadow -Wnon-virtual-dtor -pedantic`.

### Libraries
- **Google Test (gtest)**: Required for compiling and running the unit tests. Ensure you have Google Test installed on your system as it uses `-lgtest -lgtest_main -pthread` flags for linking.

- **Python Scapy**: Scapy is a packet manipulation tool for computer networks. Library is required for run `python3` script which checks that all packet subsets that need to be captured are captured by the sniffer.  

The `Scapy` library can be installed on Ubuntu by command:
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

## User's possibilities 


## Required theory
In order to use the program correctly and to understand its output, it is necessary to have a certain base of knowledge in your head, which is described in this chapter.
The chapter also contains examples of the program output for specific protocol.

### Packets  
In networking, a packet is a small segment of data divided from a larger message, suitable for transmission over computer networks like the Internet. This method allows for the reassembly of the original message by the receiving device. Using packets enables the internet to function as a packet-switching network, where data can be sent in small pieces that travel independently over various paths. [1]

Each packet includes a header and a payload. The header provides essential information such as the packet's origin, destination, and sequence, which helps the receiving device process and reorder the packets correctly. Beyond headers, packets can also have trailers or footers, added by specific network protocols, that contain additional data about the packet. [2]

### Sniffed packet types

#### Why we use packets?
In Network do not use just one packet type but use multiple packet types to accommodate different types of data and optimize network performance. By using multiple packet types, the network can tailor packet handling and processing specifically to the needs of different types of data. [3]

Another reason for using multiple packet types is to support various communication patterns, such as TCP vs UDP, single flow vs multiple flows, and different container networking technologies, such as those found in Windows and Linux. Futhermore security is also one of the reasons for using multiple packet types. Using multiple packet types in a network offers several benefits.

#### Transmission Control Protocol (TCP)
Transmission Control Protocol (TCP) is a foundational technology for the Internet, characterized as a connection-oriented protocol. It facilitates reliable data transmission between devices and applications across networks by ensuring data delivery is verified. TCP is preferred for its reliability in ensuring complete and accurate data transfer. However, this reliability comes with higher bandwidth consumption due to its extensive feedback and error-handling mechanisms. [4]

TCP is used for loading web pages via HTTP (Hypertext Transfer Protocol) and HTTPS (HTTP Secure). Protocols such as SMTP (Simple Mail Transfer Protocol) for sending emails, POP (Post Office Protocol) and IMAP (Internet Message Access Protocol) for retrieving emails, rely on TCP to ensure messages are sent and received without errors. Also another protocols like FTP (File Transfer Protocol), SFTP (SSH File Transfer Protocol), SLL (Secure Sockets Layer), etc.

```
ipk@ipk:~/ipk-proj-2$ sudo ./ipk-sniffer -i wlp4s0 --tcp
==========================================================================
Timestamp:                2024-04-21T17:48:13.538416+00:00
Source MAC:               64:fd:96:92:fb:72
Destination MAC:          14:5a:fc:50:b8:4f
Frame Length:             66 bytes
Source IP:                54.173.95.250
Destination IP:           192.168.1.21
TTL:                      245
Source Port:              443
Destination port:         43820
Sequence Number:          150434667
Acknowledgment Number:    1124707723
Flags:                    00010000
Window Size:              27

0x0000: 14 5a fc 50 b8 4f 64 fd 96 92 fb 72 08 00 45 00  .Z.P.Od. ...r..E.
0x0010: 00 34 ad d6 40 00 f5 06 7f 88 36 ad 5f fa c0 a8  .4..@... ..6._...
0x0020: 01 15 01 bb ab 2c 08 f7 73 6b 43 09 ad 8b 80 10  .....,.. skC.....
0x0030: 00 1b 13 0b 00 00 01 01 08 0a 9c ca 2c 1e 68 b1  ........ ....,.h.
0x0040: bf b9                                            ..
```

#### User Datagram Protocol (UDP)
User Datagram Protocol (UDP) is a communication protocol that facilitates the transmission of data across networks without establishing a connection or verifying the delivery of data. It is often referred to as a "connectionless" or "fire-and-forget" protocol because it sends data without ensuring that it reaches the recipient. This trait makes UDP particularly suitable for real-time applications where speed is more critical than reliability. [4]

```
ipk@ipk:~/ipk-proj-2$~/ipk-proj-2$ sudo ./ipk-sniffer -i wlp4s0 --udp
==========================================================================
Timestamp:                2024-04-21T17:49:02.660997+00:00
Source MAC:               14:5a:fc:50:b8:4f
Destination MAC:          64:fd:96:92:fb:72
Frame Length:             99 bytes
Source IP:                192.168.1.21
Destination IP:           8.8.8.8
TTL:                      64
Source Port:              55851
Destination Port:         53
UDP Length:               65 bytes

0x0000: 64 fd 96 92 fb 72 14 5a fc 50 b8 4f 08 00 45 00  d....r.Z .P.O..E.
0x0010: 00 55 ec 1b 40 00 40 11 7c af c0 a8 01 15 08 08  .U..@.@. |.......
0x0020: 08 08 da 2b 00 35 00 41 d2 1f 6b 56 01 20 00 01  ...+.5.A ..kV. ..
0x0030: 00 00 00 00 00 01 10 6e 6f 74 69 66 69 65 72 2d  .......n otifier-
0x0040: 63 6f 6e 66 69 67 73 08 61 69 72 62 72 61 6b 65  configs. airbrake
0x0050: 02 69 6f 00 00 01 00 01 00 00 29 04 b0 00 00 00  .io..... ..).....
0x0060: 00 00 00                                         ...
```

#### Internet Control Message Protocol (ICMP)
The Internet Control Message Protocol (ICMP) is a network layer protocol that plays a crucial role in diagnosing and reporting network communication issues. It is widely used by network devices like routers to ensure data is reaching its intended destination efficiently and to handle errors in network communications. ICMP does not establish a connection before sending messages. [5]

```
ipk@ipk:~/ipk-proj-2$~/ipk-proj-2$ sudo ./ipk-sniffer -i wlp4s0 --icmp4
==========================================================================
Timestamp:                2024-04-21T17:51:16.206455+00:00
Source MAC:               14:5a:fc:50:b8:4f
Destination MAC:          64:fd:96:92:fb:72
Frame Length:             98 bytes
Source IP:                192.168.1.21
Destination IP:           142.251.36.100
TTL:                      64
ICMPv4 Type:              8
ICMPv4 Code:              0

0x0000: 64 fd 96 92 fb 72 14 5a fc 50 b8 4f 08 00 45 00  d....r.Z .P.O..E.
0x0010: 00 54 a2 61 40 00 40 01 23 2b c0 a8 01 15 8e fb  .T.a@.@. #+......
0x0020: 24 64 08 00 f0 01 b1 4b 00 01 14 52 25 66 00 00  $d.....K ...R%f..
0x0030: 00 00 5b 26 03 00 00 00 00 00 10 11 12 13 14 15  ..[&.... ........
0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25  ........ .. !"#$%
0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35  &'()*+,- ./012345
0x0060: 36 37                                            67

```

```
ipk@ipk:~/ipk-proj-2$~/ipk-proj-2$ sudo ./ipk-sniffer -i wlp4s0 --icmp6
==========================================================================
Timestamp:                2024-04-21T17:53:16.746238+00:00
Source MAC:               62:16:f3:b0:24:af
Destination MAC:          00:1a:2b:3c:4d:5e
Frame Length:             62 bytes
Source IP:                fdeb:446c:912d:8da::
Destination IP:           2001:db8::1
ICMPv6 Type:              128
ICMPv6 Code:              0

0x0000: 00 1a 2b 3c 4d 5e 62 16 f3 b0 24 af 86 dd 60 00  ..+<M^b. ..$...`.
0x0010: 00 00 00 08 3a 40 fd eb 44 6c 91 2d 08 da 00 00  ....:@.. Dl.-....
0x0020: 00 00 00 00 00 00 20 01 0d b8 00 00 00 00 00 00  ...... . ........
0x0030: 00 00 00 00 00 01 80 00 75 a3 00 00 00 00        ........ u.....
```

**Note:** Sniffer is able to sniff ICMPv4 and ICMPv6 packet.

#### Internet Group Management Protocol (IGMP)
The Internet Group Management Protocol (IGMP) is a network layer protocol used primarily in IPv4 networks to facilitate the management of multicast groups. IGMP allows multiple devices to share a single IP address designated for multicasting, enabling them to receive the same data simultaneously. IGMP operates by allowing devices on a network to communicate their interest in joining or leaving multicast groups. Routers supporting IGMP listen to these transmissions to maintain a record of which devices are members of specific multicast groups. Multicast IP addresses, which range from 224.0.0.0 to 239.255.255.255, are used exclusively for these groups. When data is sent to a multicast group, the router replicates the packets and distributes them to all members of the group. [6]

```
ipk@ipk:~/ipk-proj-2$~/ipk-proj-2$ sudo ./ipk-sniffer -i wlp4s0 --igmp
==========================================================================
Timestamp:                2024-04-21T17:50:03.465119+00:00
Source MAC:               14:5a:fc:50:b8:4f
Destination MAC:          01:00:5e:00:00:fb
Frame Length:             46 bytes
Source IP:                192.168.1.21
Destination IP:           224.0.0.251
TTL:                      1
IGMP Type:                22
IGMP Max Resp Time:       0
IGMP Group Address:       224.0.0.251

0x0000: 01 00 5e 00 00 fb 14 5a fc 50 b8 4f 08 00 46 c0  ..^....Z .P.O..F.
0x0010: 00 20 00 00 40 00 01 02 41 5f c0 a8 01 15 e0 00  . ..@... A_......
0x0020: 00 fb 94 04 00 00 16 00 09 04 e0 00 00 fb        ........ ......
```

#### Address Resolution Protocol (ARP)
The Address Resolution Protocol (ARP) is a fundamental protocol used in local area networks (LANs) to associate the dynamic Internet Protocol (IP) addresses with the fixed physical machine addresses, or Media Access Control (MAC) addresses. This association is essential because IP addresses (used in the network layer) and MAC addresses (used in the data link layer) differ in format and function. ARP operates by translating the 32-bit IP address (commonly IPv4) into a 48-bit MAC address and vice versa, allowing devices on a network to identify and communicate with each other effectively. When a device on a LAN needs to communicate with another device, it uses ARP to find the MAC address associated with the intended IP address. [7]

```
ipk@ipk:~/ipk-proj-2$~/ipk-proj-2$ sudo ./ipk-sniffer -i wlp4s0 --arp
==========================================================================
Timestamp:                2024-04-21T17:54:05.283216+00:00
Source MAC:               64:fd:96:92:fb:72
Destination MAC:          14:5a:fc:50:b8:4f
Frame Length:             52 bytes
Sender MAC:               64:fd:96:92:fb:72
Sender IP:                192.168.1.1
Target MAC:               00:00:00:00:00:00
Target IP:                192.168.1.21

0x0000: 14 5a fc 50 b8 4f 64 fd 96 92 fb 72 08 06 00 01  .Z.P.Od. ...r....
0x0010: 08 00 06 04 00 01 64 fd 96 92 fb 72 c0 a8 01 01  ......d. ...r....
0x0020: 00 00 00 00 00 00 c0 a8 01 15 00 00 00 00 00 00  ........ ........
0x0030: 00 00 00 00                                      ....
```

#### Neighbor Discovery Protocol (NDP)
The Neighbor Discovery Protocol (NDP) is a crucial protocol used with IPv6, functioning at Layer 2 (Data Link Layer) of the OSI model. NDP performs several key tasks essential for efficient and consistent data transmission across IPv6 networks. These tasks include stateless address autoconfiguration, address resolution, Neighbor Unreachability Detection (NUD), and Duplicate Address Detection (DAD). NDP replaces the Address Resolution Protocol (ARP) used in IPv4, adapting these functions to the IPv6 environment. [8]

```
ipk@ipk:~/ipk-proj-2$~/ipk-proj-2$ sudo ./ipk-sniffer -i wlp4s0 --ndp
==========================================================================
Timestamp:                2024-04-21T17:54:53.819901+00:00
Source MAC:               7c:24:99:f2:cb:05
Destination MAC:          33:33:ff:cf:57:b9
Frame Length:             86 bytes
Source IP:                fe80::101c:7ef8:7f29:3421
Destination IP:           ff02::1:ffcf:57b9
ICMPv6 Type:              135
ICMPv6 Code:              0
ICMPv6 Subtype:           NDP - Neighbor Solicitation

0x0000: 33 33 ff cf 57 b9 7c 24 99 f2 cb 05 86 dd 60 00  33..W.|$ ......`.
0x0010: 00 00 00 20 3a ff fe 80 00 00 00 00 00 00 10 1c  ... :... ........
0x0020: 7e f8 7f 29 34 21 ff 02 00 00 00 00 00 00 00 00  ~..)4!.. ........
0x0030: 00 01 ff cf 57 b9 87 00 ce 1f 00 00 00 00 fe 80  ....W... ........
0x0040: 00 00 00 00 00 00 18 d0 56 20 6b cf 57 b9 01 01  ........ V k.W...
0x0050: 7c 24 99 f2 cb 05                                |$....
```

#### Multicast Listener Discovery Protocol (MLD)
IPv6 Multicast Listener Discovery (MLD) is a protocol used by IPv6 devices to identify and manage the presence of multicast listeners on a network. These listeners are nodes interested in receiving multicast packets addressed to specific multicast groups. MLD is integral to the efficient operation of IPv6 multicast routing and is implemented in two versions: MLD version 1 and MLD version 2, based on IGMP versions for IPv4. MLDv1 corresponds to IGMPv2 for IPv4 and is used for basic multicast listener functions. MLDv2 is based on IGMPv3, that supports more advanced features such as source filtering, allowing nodes to specify which sources they are interested in receiving multicast data from. [9]

```
ipk@ipk:~/ipk-proj-2$~/ipk-proj-2$ sudo ./ipk-sniffer -i wlp4s0 --mld
==========================================================================
Timestamp:                2024-04-21T17:55:25.799535+00:00
Source MAC:               14:5a:fc:50:b8:4f
Destination MAC:          33:33:00:00:00:16
Frame Length:             62 bytes
Source IP:                2001:db8:85a3::8a2e:370:7334
Destination IP:           ff02::16
ICMPv6 Type:              143
ICMPv6 Code:              0
ICMPv6 Subtype:           MLDv2 - Report

0x0000: 33 33 00 00 00 16 14 5a fc 50 b8 4f 86 dd 60 00  33.....Z .P.O..`.
0x0010: 00 00 00 08 3a 01 20 01 0d b8 85 a3 00 00 00 00  ....:. . ........
0x0020: 8a 2e 03 70 73 34 ff 02 00 00 00 00 00 00 00 00  ...ps4.. ........
0x0030: 00 00 00 00 00 16 8f 00 bd 74 00 00 00 00        ........ .t....
```

## Testing
The correct functionality and behaviour of ipk-sniffer has been tested in a number of ways - manually, by automatic tests and by [Wireshark](https://www.wireshark.org/).

### Manual Testing
The manual testing of the program was ongoing at the beginning of the program development and is divided into two parts. To check the program properly, python scripts were created to send a certain packet and ipk-sniffer was to capture it. See the tests/send_packet folder containing the python scripts.

#### Transmission Control Protocol Test Scenarios
*Terminal 1.* Runs `ipk-sniffer` with option `--source-port 5200 --tcp/-t`.  
*Terminal 2.* Sends TCP packet from port 5200.  
*Expected outcome* Sniffed TCP packet with from source port 5200 *Terminal 1*.  
  
*Terminal 1.* Runs `ipk-sniffer` with option `--destination-port 5200 --tcp/-t`.  
*Terminal 2.* Sends TCP packet to port 5200.  
*Expected outcome* Sniffed TCP packet with destination port 5200 *Terminal 1*.  

*Terminal 1.* Runs `ipk-sniffer` with option `--port/-p 5200 --tcp/-t`.  
*Terminal 2.* Sends TCP packet to/from port 5200.  
*Expected outcome* Sniffed TCP packet with source/destination port 5200 *Terminal 1*.  

#### User Datagram Protocol Test Scenarios
*Terminal 1.* Runs `ipk-sniffer` with option `--source-port 5200 --udp/-u`.  
*Terminal 2.* Sends UDP packet from port 5200.  
*Expected outcome* Sniffed UDP packet with from source port 5200 *Terminal 1*.  

*Terminal 1.* Runs `ipk-sniffer` with option `--destination-port 5200 --udp/-u`.  
*Terminal 2.* Sends UDP packet to port 5200.  
*Expected outcome* Sniffed UDP packet with destination port 5200 *Terminal 1*.  

*Terminal 1.* Runs `ipk-sniffer` with option `--port/-p 5200 --udp/-u`.  
*Terminal 2.* Sends UDP packet to/from port 5200.  
*Expected outcome* Sniffed UDP packet with source/destination port 5200 *Terminal 1*.  

#### Multicast Listener Discovery Protocol Test Scenarios
*Terminal 1.* Runs `ipk-sniffer` with option `--mld`.  
*Terminal 2.* Sends `MLDv1 Query` packet.  
*Expected outcome* Sniffed `MLDv2 Query` packet in *Terminal 1*.  
**Note:** Also other MLD packets were tested as well (e.g.`MLDv1 Report`, `MLDv1 Done`,`MLDv2 Report`).

#### Neighbor Discovery Protocol Test Scenarios
*Terminal 1.* Runs `ipk-sniffer` with option `-i virt0 --ndp`.  
*Terminal 2.* Sends `ICMPv6 Router Solicitation` packet.  
*Expected outcome* Sniffed `ICMPv6 Router Solicitation` packet in *Terminal 1*.  

**Note:** Also other NDP packets were tested as well (e.g.`ICMPv6 Router Advertisement`, `ICMPv6 Neighbor Solicitation` and `CMPv6 Neighbor Advertisement`).

#### Address Resolution Protocol Test Scenarios
*Terminal 1.* Runs `ipk-sniffer` with option ``-i virt0 --arp`.  
*Terminal 2.* Sends `ARP Request` packet.  
*Expected outcome* Sniffed `ARP Request` packet in *Terminal 1*.  
**Note:** Also other ARP packet was tested as well (e.g.`ARP Reply`).

#### Internet Control Message Protocol v4 Test Scenarios
*Terminal 1.* Runs `ipk-sniffer` with option ``-i virt0 --icmp4`.  
*Terminal 2.* Sends `ICMPv4 Echo Reply` packet.  
*Expected outcome* Sniffed `ICMPv4 Echo Reply` packet in *Terminal 1*.  
**Note:** Also other ICMPv4 packet was tested as well (e.g.`ICMPv4 Echo Request`).

#### Internet Control Message Protocol v6 Test Scenarios
*Terminal 1.* Runs `ipk-sniffer` with option ``-i virt0 --icmp6`.  
*Terminal 2.* Sends `ICMPv6 Echo Request` packet.  
*Expected outcome* Sniffed `ICMPv6 Echo Request` packet in *Terminal 1*.  
**Note:** Also other ICMPv4 packet was tested as well (e.g.`ICMPv6 Echo Reply`).

#### Internet Control Message Protocol v6 Test Scenarios
*Terminal 1.* Runs `ipk-sniffer` with option ``-i virt0 --icmp6`.  
*Terminal 2.* Sends `ICMPv6 Echo Request` packet.  
*Expected outcome* Sniffed `ICMPv6 Echo Request` packet in *Terminal 1*.  
**Note:** Also other ICMPv6 packet was tested as well (e.g.`ICMPv6 Echo Reply`), it's also possible during the actual use it is possible to sniff also MLD and NDL packets, as they are subtypes.

#### Internet Group Message Protocol v6 Test Scenarios
*Terminal 1.* Runs `ipk-sniffer` with option ``-i virt0 --igmp`  
*Terminal 2.* Sends `IGMP Query` packet  
*Expected outcome* Sniffed `IGMP Query` packet in *Terminal 1*  
**Note:** Also other ICMPv6 packet was tested as well (e.g.`IGMP Report`,`IGMP Leave Group`)  

The manual tests were performed on the virtual interface `virt0`, it was chosen as the test interface because of the network traffic, if the `wlp4s0`  environment was used, there would be a high probability that the captured packet would not be the right one.

### Automated Testing
Automatic tests are an extension of manual tests, i.e. they perform the same tests and at the same time extend them, thanks to automation it was possible to expose the program to tests with a large number of captured packets, some of the test scenarios are described below.

#### Sniff 100 of Packets of Same Group Test Scenarios
*Test Case:* Runs `ipk-sniffer` with option `-i wlp4s0 --group -n 100`, where packet `group` can be `tcp`,`udp`,`ndp`,`icmp4`,`icmp6`,`igmp`.  
*Expected Output:* Sniffed 100 packets of specific packet groups.  

#### Combinations of Sniffed Packets Test Scenarios
*Test Case:* Runs `ipk-sniffer` with option `-i wlp4s0 --group1 --group2`, where packet `group1` and `group2` can be mixture of `tcp`,`udp`,`ndp`,`icmp4`,`icmp6`,`igmp`.   
*Expected Output:* Sniffed packet of are from `group1` or `group2`.  

**Note:** As another test cases were combinations of multiple packet groups and the sniffed packets were expected to be found from the groups defined in the program arguments (e.g. `./ipk-sniffer -i wlp4s0 --tcp --ndp -igmp -icmp4` -> expected packets from groups: `tcp`,`ndp`,`icmp4`,`igmp`).  

#### Packets Sent By the Script Test Scenario
*Test Case:* Packets sent with a certain source and destination address and a fixed payload.  
*Expected Output:* Captured packets with only the expected source and destination addresses. Tested on the interface `virt0` and `wlp4s0`.  

### Wireshark 
To verify the displayed packet information and packet display, the program was also verified using Wireshark.

### Tested Enviroment 
Testing was processed on Ubuntu 22.04, Reference Ubuntu Virtual Machine And Ubuntu with Nix Enviroment. Settings of Ubuntu VM and Nix Enviroment is described [here](https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master).

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