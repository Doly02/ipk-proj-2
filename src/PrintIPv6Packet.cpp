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
            struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(ip6_hdr + 1);
            // Specifies the ICMPv6 Message Type (e.g. 128] Echo Request -> echo request, used in ping, [129] Echo Reply -> echo reply, used in ping
            // [134] Router Advertisement, [135] Neighbor Solicitation, [136] Neighbor Advertisement)
            std::cout << "ICMPv6 type: " << static_cast<int>(icmp6_hdr->icmp6_type) << std::endl;
            // Provides Additional Context or Specification for the ICMPv6 Message Type
            // The Code Specifies the Reason or Manner in Which the Message was Generated, Depending on the Message Type
            // (e.g. For Type [1] -> Different Codes Can Indicate Different Reasons Why the Destination is Unreachable, Such as:
            // Code 0: no Route to the Destination, Code 1: Communication With the Destination Administratively )
            std::cout << "ICMPv6 code: " << static_cast<int>(icmp6_hdr->icmp6_code) << std::endl;
            break;
        }
    }
}
