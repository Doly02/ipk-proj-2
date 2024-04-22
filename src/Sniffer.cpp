/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      IPv4packetSniffer.cpp
 *  Author:         Tomas Dolak
 *  Date:           11.04.2024
 *  Description:    Implements Parsing Sniffer Configuration.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           IPv4packetSniffer.cpp
 *  @author         Tomas Dolak
 *  @date           11.04.2024
 *  @brief          Implements Parsing Sniffer Configuration.
 * ****************************/

/************************************************/
/*                  Libraries                   */
/************************************************/
#include "../include/Sniffer.hpp"
#include "../include/macros.hpp"
#include <iostream>

Sniffer* Sniffer::currentInstance = nullptr;
/************************************************/
/*               Class Methods                  */
/************************************************/

/**
 * @brief Construct a new IPv4PacketSniffer::IPv4PacketSniffer object
 * 
 * @param interfaceName Interface on which the sniffer will be listening 
 * @param filter filter expression
 * @param maxPackets Maximum number of packets to capture
*/
Sniffer::Sniffer(const std::string& interfaceName, const std::string& filter, int maxPackets)
    :   interfaceName(interfaceName), 
        filterExpression(filter), 
        maxPackets(maxPackets), 
        deviceHandle(nullptr) {
        setupDevice(); // Setup device
        currentInstance = this;
}
/**
 * @brief Destruct a new IPv4PacketSniffer::IPv4PacketSniffer object
 * 
*/
Sniffer::~Sniffer() {
    if (deviceHandle) {
        pcap_close(deviceHandle);  // Close pcap Handle
    }
    if (currentInstance == this) {
        currentInstance = nullptr;  // Delete Pointer To Current Instance
    }
}

void Sniffer::handleSignal(int signal) {
    if (Sniffer::currentInstance && signal == SIGINT) {
        pcap_breakloop(Sniffer::currentInstance->deviceHandle); // Safety Break Loop
    }
}

std::string Sniffer::createPadding(int size) {
    return std::string(size, ' ');  // Create Padding
}

/**
 * @brief Setups the device for capturing packets
 * 
*/
void Sniffer::setupDevice() {
    // Open Device for Packet Capture With Set Buffer Size And With TimeOut
    deviceHandle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (deviceHandle == nullptr) {
        throw std::runtime_error("pcap_open_live failed: " + std::string(errbuf));  // If Fails Throw Exception
    }
    applyFilter();  // Apply The Filter
}

/**
 * @brief Applies The Filter From An Argument As pcap Library Filter
 * 
*/
void Sniffer::applyFilter() {
    struct bpf_program fp;  // Struct For Compiled Filter
    bpf_u_int32 net = 0;    // 'net' Used In Case When Net Is Not Needed

    // Compile The Filter For Device
    if (pcap_compile(deviceHandle, &fp, filterExpression.c_str(), 0, net) == -1) {
        throw std::runtime_error("pcap_compile failed: " + std::string(pcap_geterr(deviceHandle)));
    }

    // Apply The Filter On The Device 
    if (pcap_setfilter(deviceHandle, &fp) == -1) {
        pcap_freecode(&fp);  // Deallocate The Resources For Filter
        throw std::runtime_error("pcap_setfilter failed: " + std::string(pcap_geterr(deviceHandle)));
    }

    pcap_freecode(&fp);  // Deallocated Resources After The Filter's Application
}

/**
 * @brief Starts The Packet Capture on Device With Applied Filter
 * 
*/
void Sniffer::startCapture() {

    // Call of pcap_loop for Continual Packet Capturing According to The Filter and Number of Packets
    pcap_loop(deviceHandle, maxPackets, [](u_char *, const struct pcap_pkthdr *header, const u_char *packet) {
    printPacket(packet, header);
    }, nullptr);
}


void Sniffer::printPacket(const u_char *packet, const struct pcap_pkthdr *header) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    std::cout << "========================================================================== " << std::endl;
    std::cout << "Timestamp: "          << createPadding(15) << formatTimestamp(header->ts) << std::endl;
    std::cout << "Source MAC: "         << createPadding(14) << formatMac(eth_header->ether_shost) << std::endl;
    std::cout << "Destination MAC: "    << createPadding(9)  << formatMac(eth_header->ether_dhost) << std::endl;
    std::cout << "Frame Length: "       << createPadding(12) << header->len << " bytes" << std::endl;

    // Check If Packet Is ARP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));
        std::cout << "Sender MAC: "     << createPadding(14) << formatMac(arp_hdr->arp_sha) << std::endl;
        std::cout << "Sender IP: "      << createPadding(15) << inet_ntoa(*((struct in_addr *)arp_hdr->arp_spa)) << std::endl;
        std::cout << "Target MAC: "     << createPadding(14) << formatMac(arp_hdr->arp_tha) << std::endl;
        std::cout << "Target IP: "      << createPadding(15) << inet_ntoa(*((struct in_addr *)arp_hdr->arp_tpa)) << std::endl;
    } 
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
        std::cout << "Source IP: "      << createPadding(15) << formatIp(ip_hdr->ip_src) << std::endl;
        std::cout << "Destination IP: " << createPadding(10) << formatIp(ip_hdr->ip_dst) << std::endl;
        std::cout << "TTL: "            << createPadding(21) << static_cast<int>(ip_hdr->ip_ttl) << std::endl;

        switch (ip_hdr->ip_p) {
            case IPPROTO_TCP: {
                // TCP Header Extraction - This line of Code Specifies the Location of The TCP Header Within the Data Packe. 
                // The ip_hdr->ip_hl Contains the Length of The IP Header in 32-bit Words, Which is Shifted by Two Bits to Convert it to a Byte Count 
                // The Resulting IP Header Pointer (ip_hdr) Provides a Pointer to The Beginning of The TCP Header
                struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                
                // Prints the Source Port That Identifies the Application on the Sending Host. Ports Allow Multiplexing of TCP Communication on a Single Host
                std::cout << "Source Port: "            << createPadding(13) << ntohs(tcp_hdr->th_sport) << std::endl;
                
                // Prints the Destination Port, Which Identifies the Target Application on the Receiving Host. 
                std::cout << "Destination port: "       << createPadding(8) << ntohs(tcp_hdr->th_dport) << std::endl;
                std::cout << "Sequence Number: "        << createPadding(9) << ntohl(tcp_hdr->th_seq) << std::endl;
                std::cout << "Acknowledgment Number: "  << createPadding(3) << ntohl(tcp_hdr->th_ack) << std::endl;
                std::cout << "Flags: "                  << createPadding(19) << std::bitset<8>(tcp_hdr->th_flags) << std::endl;
                std::cout << "Window Size: "            << createPadding(13) << ntohs(tcp_hdr->th_win) << std::endl;
                break;
            }
            case IPPROTO_UDP: {
                // UDP Header Extraction - This Line Calculates the Position of The UDP header in The Packet Mix
                // ip_hdr->ip_hl Indicates the Length of The IP Header in 32-bit Words, Which Is Shifted Two Bits to The Left
                // The Result Is Added to The Pointer to The Beginning of The IP Header (ip_hdr), Which Gives a Pointer to The Beginning of The UDP Header
                struct udphdr *udp_hdr = (struct udphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                
                // Prints the Source Port of the UDP Packet (Ports are Used to Address Specific Applications or Services on the Host)
                std::cout << "Source Port: "            << createPadding(13) << ntohs(udp_hdr->uh_sport) << std::endl;
                
                // Destination Port Identifies the Application or Service on the Target Host
                std::cout << "Destination Port: "       << createPadding(8) << ntohs(udp_hdr->uh_dport) << std::endl;

                // UDP Length - The Total Length of the UDP Header and Data, Which is Important for Understanding the Size of the Data Being Transferred.
                std::cout << "UDP Length: "             << createPadding(14) << ntohs(udp_hdr->uh_ulen) << " bytes" << std::endl;
                break;
            }
            case IPPROTO_ICMP: {
                // ICMP Header Extraction
                struct icmphdr *icmp_hdr = (struct icmphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                
                // Type of ICMP Message (e.g. Echo Request [8], Echo Reply [0], Destination Unreachable [3],.. -> Identifies What Message Signalizes)
                std::cout << "ICMPv4 Type: "              << createPadding(13) << static_cast<int>(icmp_hdr->type) << std::endl;
                
                // Information About What Caused the ICMP message - For Type 3 (Destination Unreachable), 
                // the Code Specifies the Reason Why the Destination is Unreachable, such as 'Port Unreachable' (code 3) or 'Network Unreachable' (code 0)
                std::cout << "ICMPv4 Code: "              << createPadding(13) << static_cast<int>(icmp_hdr->code) << std::endl;
                break;
            }
            case IPPROTO_IGMP: {
                // IGMP Header (Extracts Specific Informations For IGMP Message)
                struct igmp *igmp_hdr = (struct igmp *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                
                // Type of Typ IGMP Message (e.g. Query, Report)
                std::cout << "IGMP Type: "              << createPadding(15) << static_cast<unsigned>(igmp_hdr->igmp_type) << std::endl;
                
                // Max Response Time (Used in IGMP Query)
                std::cout << "IGMP Max Resp Time: "     << createPadding(6) << static_cast<unsigned>(igmp_hdr->igmp_code) << std::endl;
                
                // Target Group Adress For IGMP Message
                std::cout << "IGMP Group Address: "     << createPadding(6) << inet_ntoa(igmp_hdr->igmp_group) << std::endl;
                break;                
            }
        }
    }
    else if (ntohs(eth_header->ether_type)  == ETHERTYPE_IPV6) { /* IPv6 Packets */
        processIPv6Packet(packet);

    }
    std::cout << std::endl;
    std::cout << formatHex(packet, header->caplen) << std::endl;
}


