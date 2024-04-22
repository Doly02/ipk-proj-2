/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      PrintIPv4Packet.cpp
 *  Author:         Tomas Dolak
 *  Date:           15.04.2024
 *  Description:    Implements Functions For IPv4 Packet Information Printing.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           PrintIPv4Packet.cpp
 *  @author         Tomas Dolak
 *  @date           15.04.2024
 *  @brief          Implements Functions For IPv6 Packet Information Printing.
 * ****************************/

/************************************************/
/*                  Libraries                   */
/************************************************/
#include "../include/Sniffer.hpp"
#include "../include/macros.hpp"
/************************************************/
/*             Class Implementation             */
/************************************************/
void Sniffer::processIPv6Packet(const uint8_t *packet) {
    struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

    std::cout << "Source IP: " << createPadding(15) << src_ip << std::endl;
    std::cout << "Destination IP: " << createPadding(10) << dst_ip << std::endl;

    // Process The Header By Type
    int next_header = ip6_hdr->ip6_nxt;
    switch (next_header) {
        case IPPROTO_UDP: {
            struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            std::cout << "Source Port: " << createPadding(13) << ntohs(udp_hdr->source) << std::endl;
            std::cout << "Destination Port: " << createPadding(8) << ntohs(udp_hdr->dest) << std::endl;
            std::cout << "UDP Length: " << createPadding(14) << ntohs(udp_hdr->len) << " bytes" << std::endl;
            break;
        }
        case IPPROTO_ICMPV6: {
            const struct icmp6_hdr *icmp6_hdr = findICMPv6Header(reinterpret_cast<const struct ip6_hdr *>(packet + sizeof(struct ether_header)));
            if (icmp6_hdr)
            {
                // Specifies the ICMPv6 Message Type (e.g. 128] Echo Request -> echo request, used in ping, [129] Echo Reply -> echo reply, used in ping
                // [134] Router Advertisement, [135] Neighbor Solicitation, [136] Neighbor Advertisement)
                std::cout << "ICMPv6 Type: " << createPadding(13) << static_cast<int>(icmp6_hdr->icmp6_type) << std::endl;
                // Provides Additional Context or Specification for the ICMPv6 Message Type
                // The Code Specifies the Reason or Manner in Which the Message was Generated, Depending on the Message Type
                // (e.g. For Type [1] -> Different Codes Can Indicate Different Reasons Why the Destination is Unreachable, Such as:
                // Code 0: no Route to the Destination, Code 1: Communication With the Destination Administratively )
                std::cout << "ICMPv6 Code: " << createPadding(13) << static_cast<int>(icmp6_hdr->icmp6_code) << std::endl;
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
        case MLDv1QUERY:  // MLDv1 Query
            std::cout << "ICMPv6 Subtype: " << createPadding(10) << "MLDv1 - Query" << std::endl;
            break;
        case MLDv1REPORT:  // MLDv1 Report
            std::cout << "ICMPv6 Subtype: " << createPadding(10) << "MLDv1 - Report" << std::endl;
            break;
        case MLDv1DONE:  // MLDv1 Done
            std::cout << "ICMPv6 Subtype: " << createPadding(10) << "MLDv1 - Done" << std::endl;
            break;
        case MLDv2REPORT:  // MLDv2 Report
            std::cout << "ICMPv6 Subtype: " << createPadding(10) << "MLDv2 - Report" << std::endl;;
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
            std::cout << "ICMPv6 Subtype: " << createPadding(10) << "NDP - Router Solicitation" << std::endl;
            break;

        case ROUTER_ADVERTISEMENT:   
            std::cout << "ICMPv6 Subtype: " << createPadding(10) << "NDP - Router Advertisement" << std::endl;
            break;
        
        case NEIGHBOR_SOLICITATION:   
            std::cout << "ICMPv6 Subtype: " << createPadding(10) << "NDP - Neighbor Solicitation" << std::endl;
            break;

        case NEIGHBOR_ADVERTISEMENT:  
            std::cout << "ICMPv6 Subtype: " << createPadding(10) << "NDP - Neighbor Advertisement" << std::endl;
            break;

        case REDIRECT:  
            std::cout << "ICMPv6 Subtype: " << createPadding(10) << "NDP - Redirect Message" << std::endl;
            break;
            
        default:
            break;
    }
}