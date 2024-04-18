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
}
/**
 * @brief Destruct a new IPv4PacketSniffer::IPv4PacketSniffer object
 * 
*/
Sniffer::~Sniffer() {
    if (deviceHandle) {
        pcap_close(deviceHandle);  // Close pcap Handle
    }
}


void Sniffer::processMLDPacket(const u_char *packet, const struct pcap_pkthdr *header) {
    //const struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    const struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    printf("ICMP6 type: %d\n", icmp6->icmp6_type);
    if (icmp6->icmp6_type == 130 || icmp6->icmp6_type == 131 || icmp6->icmp6_type == 132 || icmp6->icmp6_type == 143) {
        std::cout << "MLD message detected, type: " << static_cast<int>(icmp6->icmp6_type) << std::endl;
        //actNumMldPackets++;
        //if (actNumMldPackets >= maxPackets) {
        //    pcap_breakloop(deviceHandle);
        //}
    }
    else if (header)
        return;
}


/**
 * @brief Setups the device for capturing packets
 * 
*/
void Sniffer::setupDevice() {
    // Open Device for Packet Capture With Set Buffer Size And With TimeOut
    printf("Interface: %s\n", interfaceName.c_str());
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

    printf("Filter: %s\n", filterExpression.c_str());
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

std::string Sniffer::formatMac(const u_char* mac) {
    std::ostringstream stream;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(mac[i]);
        if (i < ETHER_ADDR_LEN - 1) stream << ":";
    }
    return stream.str();
}

std::string Sniffer::formatIp(in_addr ip_addr) {
    return inet_ntoa(ip_addr);
}

std::string Sniffer::formatTimestamp(const struct timeval& tv) {
    std::time_t nowtime = tv.tv_sec;
    struct tm *nowtm = std::gmtime(&nowtime);
    char tmbuf[64], buf[64];
    std::strftime(tmbuf, sizeof tmbuf, "%Y-%m-%dT%H:%M:%S", nowtm);
    std::snprintf(buf, sizeof buf, "%s.%06ld+00:00", tmbuf, (long)tv.tv_usec);
    return buf;
}

std::string Sniffer::formatHex(const u_char *data, size_t length) {
    std::ostringstream stream;
    std::string ascii;
    int bytes_per_line = 16;  // Standard Number of Bytes On Line

    for (size_t i = 0; i < length; ++i) {
        // On The Beggining of Every Line Print Offset 
        if (i % bytes_per_line == 0) {
            if (i != 0) {
                stream << " " << ascii; // Add ASCII Representation at The End Of The Line
                ascii.clear();
                stream << std::endl; // New Line
            }
            stream << "0x" << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
        }

        // Add Hexadecimal Value of The Byte
        stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]);

        // Build ASCII Representation For Print In The End of the Line (If Char is Unpritable Print Dot)
        ascii += std::isprint(data[i]) ? static_cast<char>(data[i]) : '.';

        // Add Space Between Bytes
        stream << " ";
    }

    // Fill The Other Part of Line If Line Does Not Includes 16 Bytes
    size_t remaining = length % bytes_per_line;
    if (remaining != 0) {
        // Add Pedding To Align ASCII Output
        int padding = (bytes_per_line - remaining) * 3;
        stream << std::string(padding, ' ');
    }
    stream << " " << ascii; // Add Last ASCII Line

    return stream.str();
}


void Sniffer::printPacket(const u_char *packet, const struct pcap_pkthdr *header) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    std::cout << "=========================================================================" << std::endl;
    std::cout << "timestamp: " << formatTimestamp(header->ts) << std::endl;
    std::cout << "src MAC: " << formatMac(eth_header->ether_shost) << std::endl;
    std::cout << "dst MAC: " << formatMac(eth_header->ether_dhost) << std::endl;
    std::cout << "frame length: " << header->len << " bytes" << std::endl;

    // Check If Packet Is ARP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));
        std::cout << "Sender MAC: " << formatMac(arp_hdr->arp_sha) << std::endl;
        std::cout << "Sender IP: " << inet_ntoa(*((struct in_addr *)arp_hdr->arp_spa)) << std::endl;
        std::cout << "Target MAC: " << formatMac(arp_hdr->arp_tha) << std::endl;
        std::cout << "Target IP: " << inet_ntoa(*((struct in_addr *)arp_hdr->arp_tpa)) << std::endl;
    } 
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
        std::cout << "src IP: " << formatIp(ip_hdr->ip_src) << std::endl;
        std::cout << "dst IP: " << formatIp(ip_hdr->ip_dst) << std::endl;

        switch (ip_hdr->ip_p) {
            case IPPROTO_TCP: {
                // TCP Header Extraction - This line of Code Specifies the Location of The TCP Header Within the Data Packe. 
                // The ip_hdr->ip_hl Contains the Length of The IP Header in 32-bit Words, Which is Shifted by Two Bits to Convert it to a Byte Count 
                // The Resulting IP Header Pointer (ip_hdr) Provides a Pointer to The Beginning of The TCP Header
                struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                
                // Prints the Source Port That Identifies the Application on the Sending Host. Ports Allow Multiplexing of TCP Communication on a Single Host
                std::cout << "src port: " << ntohs(tcp_hdr->th_sport) << std::endl;
                
                // Prints the Destination Port, Which Identifies the Target Application on the Receiving Host. 
                std::cout << "dst port: " << ntohs(tcp_hdr->th_dport) << std::endl;
                break;
            }
            case IPPROTO_UDP: {
                // UDP Header Extraction - This Line Calculates the Position of The UDP header in The Packet Mix
                // ip_hdr->ip_hl Indicates the Length of The IP Header in 32-bit Words, Which Is Shifted Two Bits to The Left
                // The Result Is Added to The Pointer to The Beginning of The IP Header (ip_hdr), Which Gives a Pointer to The Beginning of The UDP Header
                struct udphdr *udp_hdr = (struct udphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                
                // Prints the Source Port of the UDP Packet (Ports are Used to Address Specific Applications or Services on the Host)
                std::cout << "src port: " << ntohs(udp_hdr->uh_sport) << std::endl;
                
                // Destination Port Identifies the Application or Service on the Target Host
                std::cout << "dst port: " << ntohs(udp_hdr->uh_dport) << std::endl;
                break;
            }
            case IPPROTO_ICMP: {
                // ICMP Header Extraction
                struct icmphdr *icmp_hdr = (struct icmphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                
                // Type of ICMP Message (e.g. Echo Request [8], Echo Reply [0], Destination Unreachable [3],.. -> Identifies What Message Signalizes)
                std::cout << "ICMP type: " << static_cast<int>(icmp_hdr->type) << std::endl;
                
                // Information About What Caused the ICMP message - For Type 3 (Destination Unreachable), 
                // the Code Specifies the Reason Why the Destination is Unreachable, such as 'Port Unreachable' (code 3) or 'Network Unreachable' (code 0)
                std::cout << "ICMP code: " << static_cast<int>(icmp_hdr->code) << std::endl;
                break;
            }
            case IPPROTO_IGMP: {
                // IGMP Header (Extracts Specific Informations For IGMP Message)
                struct igmp *igmp_hdr = (struct igmp *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                
                // Type of Typ IGMP Message (e.g. Query, Report)
                std::cout << "IGMP type: " << static_cast<unsigned>(igmp_hdr->igmp_type) << std::endl;
                
                // Max Response Time (Used in IGMP Query)
                std::cout << "IGMP max resp time: " << static_cast<unsigned>(igmp_hdr->igmp_code) << std::endl;
                
                // Target Group Adress For IGMP Message
                std::cout << "IGMP group address: " << inet_ntoa(igmp_hdr->igmp_group) << std::endl;
                break;                
            }
        }
        std::cout << formatHex(packet, header->caplen) << std::endl;
    }
    else if (ntohs(eth_header->ether_type)  == ETHERTYPE_IPV6) { /* IPv6 Packets */
        processIPv6Packet(packet);
        std::cout << formatHex(packet, header->caplen) << std::endl;
    }
}

void Sniffer::processIPv6Packet(const uint8_t *packet) {
    // Extrahování IPv6 hlavičky
    struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

    // Bufery pro zdrojovou a cílovou IPv6 adresu
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    // Konverze zdrojové a cílové adresy do čitelné formy
    inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

    // Výpis zdrojové a cílové adresy
    std::cout << "src IP: " << src_ip << std::endl;
    std::cout << "dst IP: " << dst_ip << std::endl;

    // Zpracování další hlavičky dle typu
    int next_header = ip6_hdr->ip6_nxt;
    switch (next_header) {
        case IPPROTO_ICMPV6: {
            const struct icmp6_hdr *icmp6_hdr = findICMPv6Header(reinterpret_cast<const struct ip6_hdr *>(packet + sizeof(struct ether_header)));
            if (icmp6_hdr)
            {
                // Specifies the ICMPv6 Message Type (e.g. 128] Echo Request -> echo request, used in ping, [129] Echo Reply -> echo reply, used in ping
                // [134] Router Advertisement, [135] Neighbor Solicitation, [136] Neighbor Advertisement)
                std::cout << "ICMPv6 type: " << static_cast<int>(icmp6_hdr->icmp6_type) << std::endl;
                // Provides Additional Context or Specification for the ICMPv6 Message Type
                // The Code Specifies the Reason or Manner in Which the Message was Generated, Depending on the Message Type
                // (e.g. For Type [1] -> Different Codes Can Indicate Different Reasons Why the Destination is Unreachable, Such as:
                // Code 0: no Route to the Destination, Code 1: Communication With the Destination Administratively )
                std::cout << "ICMPv6 code: " << static_cast<int>(icmp6_hdr->icmp6_code) << std::endl;
                // Print MLD Type if Packet Is Subtype of MLD
                processMLDMessage(icmp6_hdr);
                processNDPMessage(icmp6_hdr);

            }
            break;
        }
    }
}

const struct icmp6_hdr* Sniffer::findICMPv6Header(const struct ip6_hdr *ip6_hdr) {
    int next_header = ip6_hdr->ip6_nxt;
    const uint8_t *next_hdr_ptr = reinterpret_cast<const uint8_t*>(ip6_hdr + 1);
    
    // Continue While ICMPv6 Header Is Not Found (Or It's Not The End of The Headers)
    while (true) {
       
        if (next_header == IPPROTO_ICMPV6) {
            // Return Pointer To The ICMPv6 Header
            return reinterpret_cast<const struct icmp6_hdr*>(next_hdr_ptr);
        }
        // Check If Header Is Not Extension Header
        if (next_header == IPPROTO_NONE || next_header == IPPROTO_FRAGMENT) {
            // End of Header or Fragment
            return nullptr;
        }
        // Load Next Header
        next_header = *next_hdr_ptr;
        unsigned int hdr_extension_length = static_cast<unsigned int>(*(next_hdr_ptr + 1));

        // Move Pointer to Next Header in String
        next_hdr_ptr += (hdr_extension_length + 1) * 8;
    }
    // Just Preventing Compiler Warning -> Should Not Be Reached
    return nullptr;
}


void Sniffer::processMLDMessage(const struct icmp6_hdr* icmp6_hdr) {
    switch (icmp6_hdr->icmp6_type) {
        case 130:  // MLDv1 Query
            std::cout << "ICMPv6 Subtype: MLDv1 - Query" << std::endl;
            break;
        case 131:  // MLDv1 Report
            std::cout << "ICMPv6 Subtype: MLDv1 - Report" << std::endl;
            break;
        case 132:  // MLDv1 Done
            std::cout << "ICMPv6 Subtype: MLDv1 - Done" << std::endl;
            break;
        case 143:  // MLDv2 Report
            std::cout << "ICMPv6 Subtype: MLDv2 - Report" << std::endl;
            break;
        default:
            break;
    }
}

void Sniffer::processNDPMessage(const struct icmp6_hdr *icmp6_hdr) {
    if (!icmp6_hdr) return;  // Ensure the ICMPv6 Header is Not NULL

    // Check the type of the ICMPv6 message to determine if it's an NDP message
    switch (icmp6_hdr->icmp6_type) {

        case ROUTER_SOLICITATION:   
            std::cout << "ICMPv6 Subtype: NDP - Router Solicitation" << std::endl;
            break;

        case ROUTER_ADVERTISEMENT:   
            std::cout << "ICMPv6 Subtype: NDP - Router Advertisement" << std::endl;
            break;
        
        case NEIGHBOR_SOLICITATION:   
            std::cout << "ICMPv6 Subtype: NDP - Neighbor Solicitation" << std::endl;
            break;

        case NEIGHBOR_ADVERTISEMENT:  
            std::cout << "ICMPv6 Subtype: NDP - Neighbor Advertisement" << std::endl;
            break;

        case REDIRECT:  
            std::cout << "ICMPv6 Subtype: NDP - Redirect Message" << std::endl;
            break;
            
        default:
            break;
    }
}
