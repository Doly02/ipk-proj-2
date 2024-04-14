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

class IPv4PacketSniffer {
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

    public:
        IPv4PacketSniffer(const std::string& interfaceName, const std::string& filter, int maxPackets);
        ~IPv4PacketSniffer();

        void startCapture();
        void stopCapture();

};
#endif // IPV4PACKET_SNIFFER_HPP