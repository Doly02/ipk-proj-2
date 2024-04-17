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
#include "../include/PrintIPv6Packet.hpp"
#include "../include/macros.hpp"
/************************************************/
/*             Function Implementation          */
/************************************************/
void processIPv6Packet(const uint8_t *packet) {
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

const struct icmp6_hdr* findICMPv6Header(const struct ip6_hdr *ip6_hdr) {
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


void processMLDMessage(const struct icmp6_hdr* icmp6_hdr) {
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

void processNDPMessage(const struct icmp6_hdr *icmp6_hdr) {
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