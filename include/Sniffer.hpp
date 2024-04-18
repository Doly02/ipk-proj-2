/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      IPv4packetSniffer.hpp
 *  Author:         Tomas Dolak
 *  Date:           11.04.2024
 *  Description:    Implements Parsing Sniffer Configuration.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           IPv4packetSniffer.hpp
 *  @author         Tomas Dolak
 *  @date           11.04.2024
 *  @brief          Implements Parsing Sniffer Configuration.
 * ****************************/
#ifndef IPV4PACKET_SNIFFER_HPP
#define IPV4PACKET_SNIFFER_HPP
/************************************************/
/*                  Libraries                   */
/************************************************/
#include "PrintIPv4Packet.hpp"
#include <pcap.h>
#include <iostream>
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
#include <netinet/igmp.h>           // For IGMP header
#include <netinet/tcp.h>            // For TCP header
#include <netinet/udp.h>            // For UDP header
#include <netinet/ip_icmp.h>        // For ICMP header
#include <netinet/ip6.h>            // For Struct ip6_hdr
#include <netinet/icmp6.h>          // For Struct icmp6_hdr
#include <arpa/inet.h>              // For inet_ntop
#include <net/ethernet.h>           // For ether_header
#include <arpa/inet.h>    


class Sniffer {
    private:
        char errbuf[PCAP_ERRBUF_SIZE];

        constexpr static int PROMISC_MODE_ON = 1;
        constexpr static int PROMISC_MODE_OFF = 0;
        constexpr static int CAPTURE_TIME_LIMIT = 1000;
        constexpr static int FAULT = -1;

        std::string interfaceName;
        std::string filterExpression;
        int maxPackets;
        pcap_t* deviceHandle;


        void setupDevice();
        void applyFilter();
        void processMLDPacket(const u_char *packet, const struct pcap_pkthdr *header);
    public:
        Sniffer(const std::string& interfaceName, const std::string& filter, int maxPackets);
        ~Sniffer();

        void startCapture();
        void stopCapture();


        static std::string formatMac(const u_char* mac);

        static std::string formatIp(in_addr ip_addr);

        static std::string formatTimestamp(const struct timeval& tv);

        static std::string formatHex(const u_char *data, size_t length);

        static void printPacket(const u_char *packet, const struct pcap_pkthdr *header);         

        static void processIPv6Packet(const uint8_t *packet);

        static const struct icmp6_hdr* findICMPv6Header(const struct ip6_hdr *ip6_hdr);

        static void processMLDMessage(const struct icmp6_hdr* icmp6_hdr);

        static void processNDPMessage(const struct icmp6_hdr *icmp6_hdr);
};
#endif // IPV4PACKET_SNIFFER_HPP