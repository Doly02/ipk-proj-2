/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      PrintIPv4Packet.cpp
 *  Author:         Tomas Dolak
 *  Date:           14.04.2024
 *  Description:    Implements Functions For IPv4 Packet Information Printing.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           PrintIPv4Packet.cpp
 *  @author         Tomas Dolak
 *  @date           14.04.2024
 *  @brief          Implements Functions For IPv4 Packet Information Printing.
 * ****************************/

/************************************************/
/*                  Libraries                   */
/************************************************/
#include "../include/PrintIPv4Packet.hpp"
#include "../include/PrintIPv6Packet.hpp"
/************************************************/
/*           Function Implementation            */
/************************************************/
std::string format_mac(const u_char* mac) {
    std::ostringstream stream;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(mac[i]);
        if (i < ETHER_ADDR_LEN - 1) stream << ":";
    }
    return stream.str();
}

std::string format_ip(in_addr ip_addr) {
    return inet_ntoa(ip_addr);
}

std::string format_timestamp(const struct timeval& tv) {
    std::time_t nowtime = tv.tv_sec;
    struct tm *nowtm = std::gmtime(&nowtime);
    char tmbuf[64], buf[64];
    std::strftime(tmbuf, sizeof tmbuf, "%Y-%m-%dT%H:%M:%S", nowtm);
    std::snprintf(buf, sizeof buf, "%s.%06ld+00:00", tmbuf, (long)tv.tv_usec);
    return buf;
}

std::string format_hex(const u_char *data, size_t length) {
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


void print_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    std::cout << "timestamp: " << format_timestamp(header->ts) << std::endl;
    std::cout << "src MAC: " << format_mac(eth_header->ether_shost) << std::endl;
    std::cout << "dst MAC: " << format_mac(eth_header->ether_dhost) << std::endl;
    std::cout << "frame length: " << header->len << " bytes" << std::endl;

    // Check If Packet Is ARP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));
        std::cout << "Sender MAC: " << format_mac(arp_hdr->arp_sha) << std::endl;
        std::cout << "Sender IP: " << inet_ntoa(*((struct in_addr *)arp_hdr->arp_spa)) << std::endl;
        std::cout << "Target MAC: " << format_mac(arp_hdr->arp_tha) << std::endl;
        std::cout << "Target IP: " << inet_ntoa(*((struct in_addr *)arp_hdr->arp_tpa)) << std::endl;
    } 
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
        std::cout << "src IP: " << format_ip(ip_hdr->ip_src) << std::endl;
        std::cout << "dst IP: " << format_ip(ip_hdr->ip_dst) << std::endl;

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
        std::cout << format_hex(packet, header->caplen) << std::endl;
    }
    else if (ntohs(eth_header->ether_type)  == ETHERTYPE_IPV6) { /* IPv6 Packets */
        printf("Packet is IPv6\n");
        processIPv6Packet(packet);
        std::cout << format_hex(packet, header->caplen) << std::endl;
    }
}
    
