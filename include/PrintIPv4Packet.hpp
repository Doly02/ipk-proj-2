/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      PrintIPv4Packet.hpp
 *  Author:         Tomas Dolak
 *  Date:           14.04.2024
 *  Description:    Implements Functions For IPv4 Packet Information Printing.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           PrintIPv4Packet.hpp
 *  @author         Tomas Dolak
 *  @date           14.04.2024
 *  @brief          Implements Functions For IPv4 Packet Information Printing.
 * ****************************/

#ifndef IPK_PROJ_2_PRINTIPV4PACKET_HPP
#define IPK_PROJ_2_PRINTIPV4PACKET_HPP
/************************************************/
/*                  Libraries                   */
/************************************************/
#include <iostream>
#include <pcap.h>
#include <getopt.h>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>           // Change This Is For Mac OS -> For Ubuntu #include <netinet/ether.h>
#include <netinet/if_ether.h>       // For ether_header a ether_arp
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h> 
#include <arpa/inet.h>
/************************************************/
/*            Function Definitions              */
/************************************************/
std::string format_mac(const u_char* mac);

std::string format_ip(in_addr ip_addr);

std::string format_timestamp(const struct timeval& tv);

std::string format_hex(const u_char *data, size_t length);

void print_packet(const u_char *packet, const struct pcap_pkthdr *header);

#endif // IPK_PROJ_2_PRINTIPV4PACKET_HPP