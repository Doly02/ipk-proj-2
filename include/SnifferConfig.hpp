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
        bool ndp;                   //<! NDP Packets (Neighbor Discovery Protocol) 
        bool portSource;            //<! Capture On Source Port
        bool portDestination;       //<! Capture On Destination Port 
    
        int numOfProtocols;

    public:
        std::string interface;      //<! Interface on Which Will Be Sniffed 
        bool mld;                   //<! MLD Packets (Multicast Listener Discovery)
        int num;                    //<! Number of Packets to Capture
        struct Protocol {
            std::string name;
            bool isActive; 
            Protocol(const std::string& n, bool active) : name(n), isActive(active) {}
        };

        SnifferConfig(/* args */);
        ~SnifferConfig();

        /**
         * @brief Gets the Interface
         * 
         * @return std::string 
         */
        std::string getInterface() const { return interface; }
        /**
         * @brief Gets the Port
         * 
         * @return int 
         */
        int getPort() const { return port; }
        /**
         * @brief Checks If TCP Is Active
         * 
         * @return true If TCP Is Active Otherwise False
         */
        bool isTcp() const { return tcp; }
        
        /**
         * @brief Checks If UDP Is Active
         * 
         * @return true If UDP Is Active Otherwise False
         */
        bool isUdp() const { return udp; }

        /**
         * @brief Parse The Program's Arguments
         * 
         * @param argc  Count of The Arguments
         * @param argv  Values Of The Argument
         * @return int  Returns CORRECT Parsing Was Proceedd Correctly (Special Case 'JUST_INTERFACE' - If Only Argument Was '-i'/'--interface' To
         *              Show Avalaible Interfaces To The User).
         */
        int parseArguments(int argc, char *argv[]);

        /**
         * @brief Prints Program Usage To STDOUT.
         * 
         */
        void printUsage();

        /**
         * @brief Generates Filter for 'lib pcap', Dependent on Chosen Program Args.
         * 
         * @return std::string 
         */
        std::string generateFilter() const;
};


#endif // SNIFFERCONFIG_HPP



