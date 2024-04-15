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
#ifndef PRINTIPV6PACKET_HPP
#define PRINTIPV6PACKET_HPP
/************************************************/
/*                  Libraries                   */
/************************************************/
#include <iostream>
#include <netinet/ip6.h>    // For Struct ip6_hdr
#include <netinet/icmp6.h>  // For Struct icmp6_hdr
#include <arpa/inet.h>      // For inet_ntop
#include <net/ethernet.h>   // For ether_header
/************************************************/
/*             Function Definitions             */ 
/************************************************/
void processIPv6Packet(const uint8_t *packet);

#endif // PRINTIPV6PACKET_HPP

