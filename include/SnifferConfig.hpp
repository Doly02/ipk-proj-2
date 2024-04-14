/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      SnifferConfig.hpp
 *  Author:         Tomas Dolak
 *  Date:           11.04.2024
 *  Description:    Implements Parsing Sniffer Configuration.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           SnifferConfig.hpp
 *  @author         Tomas Dolak
 *  @date           11.04.2024
 *  @brief          Implements Parsing Sniffer Configuration.
 * ****************************/
#ifndef SNIFFERCONFIG_HPP
#define SNIFFERCONFIG_HPP
/************************************************/
/*                  Libraries                   */
/************************************************/
#include <iostream>
#include <getopt.h>
#include <string>
#include "macros.hpp"
#include <vector>  
/************************************************/
/*               Class Definition               */
/************************************************/

class SnifferConfig
{
    private:
        int port;                   //<! Zero Means That Port Filter is Not Enabled
        bool tcp;                   //<! TCP Packets
        bool udp;                   //<! UDP Packets
        bool arp;                   //<! ARP Packets (Address Resolution Protocol)
        bool icmp4;                 //<! ICMPv4 Packets
        bool icmp6;                 //<! ICMPv6 Packets
        bool igmp;                  //<! IGMP Packets (Internet Group Management Protocol)
        bool mld;                   //<! MLD Packets (Multicast Listener Discovery)
        bool ndp;                   //<! NDP Packets (Neighbor Discovery Protocol) 
        bool portSource;            //<! Capture On Source Port
        bool portDestination;       //<! Capture On Destination Port 
    
        int numOfProtocols;

    public:
        std::string interface;
        int num;                    //<! Number of Packets to Capture
        struct Protocol {
            std::string name;
            bool isActive; 
            Protocol(const std::string& n, bool active) : name(n), isActive(active) {}
        };

        SnifferConfig(/* args */);
        ~SnifferConfig();

        std::string getInterface() const { return interface; }
        int getPort() const { return port; }
        bool isTcp() const { return tcp; }
        bool isUdp() const { return udp; }

        int parseArguments(int argc, char *argv[]);

        void printUsage();

        std::string generateFilter() const;
};


#endif // SNIFFERCONFIG_HPP