/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      SnifferConfig.cpp
 *  Author:         Tomas Dolak
 *  Date:           11.04.2024
 *  Description:    Implements Parsing Sniffer Configuration.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           SnifferConfig.cpp
 *  @author         Tomas Dolak
 *  @date           11.04.2024
 *  @brief          Implements Parsing Sniffer Configuration.
 * ****************************/

/************************************************/
/*                  Libraries                   */
/************************************************/
#include "../include/SnifferConfig.hpp"
/************************************************/
/*               Class Methods                  */
/************************************************/


SnifferConfig::SnifferConfig()
    : port(0), tcp(false), udp(false), arp(false),
      icmp4(false), icmp6(false), igmp(false),
      mld(false), ndp(false), num(1), numOfProtocols(0),
      portSource(false), portDestination(false) {}

SnifferConfig::~SnifferConfig() {}


void SnifferConfig::parseArguments(int argc, char *argv[]) {
    int option;
    int optionIndex = 0;

    const char* shortOptions = "i:p:tu:n:";
    const struct option longOptions[] = {
        {"interface", required_argument, nullptr, 'i'},
        {"tcp", no_argument, nullptr, 't'},
        {"udp", no_argument, nullptr, 'u'},
        {"port-source", required_argument, nullptr, 'p'},
        {"port-destination", required_argument, nullptr, 'p'},
        {"arp", no_argument, nullptr, 0},
        {"icmp4", no_argument, nullptr, 0},
        {"icmp6", no_argument, nullptr, 0},
        {"igmp", no_argument, nullptr, 0},
        {"mld", no_argument, nullptr, 0},
        {"ndp", no_argument, nullptr, 0},
        {"n", required_argument, nullptr, 'n'},
        {nullptr, 0, nullptr, 0}
    };

    while ((option = getopt_long(argc, argv, shortOptions, longOptions, &optionIndex)) != -1) {
        switch (option) {
            case 'i':
                interface = optarg;
                break;
            case 't':
                tcp = true;
                break;
            case 'u':
                udp = true;
                break;
            case 'p':
                port = std::stoi(optarg);
                if (strcmp(longOptions[optionIndex].name, "port-source") == 0) {
                    portSource = true;
                } else if (strcmp(longOptions[optionIndex].name, "port-destination") == 0) {
                    portDestination = true;
                }
                break;
            case 'n':
                num = std::stoi(optarg);
                break;
            case 0:
                if (strcmp(longOptions[optionIndex].name, "arp") == 0) 
                {
                    numOfProtocols++;
                    arp = true;
                }
                else if (strcmp(longOptions[optionIndex].name, "icmp4") == 0)
                {
                    numOfProtocols++;
                    icmp4 = true;
                } 
                else if (strcmp(longOptions[optionIndex].name, "icmp6") == 0) 
                {
                    numOfProtocols++;
                    icmp6 = true;
                }
                else if (strcmp(longOptions[optionIndex].name, "igmp") == 0) 
                {
                    numOfProtocols++;
                    igmp = true;
                }
                else if (strcmp(longOptions[optionIndex].name, "mld") == 0)
                {
                    numOfProtocols++;
                    mld = true;
                }
                else if (strcmp(longOptions[optionIndex].name, "ndp") == 0)
                {
                    numOfProtocols++;
                    ndp = true;
                } 
                break;
            case '?':
                // Error in getopt, unknown option or missing option argument
                std::cerr << "Error: Invalid option or missing argument." << std::endl;
                exit(EXIT_FAILURE);
        }
    }
}


void SnifferConfig::printUsage() {
    std::cout << "Usage: ./ipk-sniffer [-i interface | --interface interface] "
              << "{-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] "
              << "[--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n";

    std::cout << "Options:\n"
              << "  -i, --interface interface\tInterface to Capture Packets\n"
              << "  -p, --port-source port\tCapture Packets With Source Port\n"
              << "  --port-destination port\tCapture Packets With Destination Port\n"
              << "  -t, --tcp\t\t\tCapture TCP Packets\n"
              << "  -u, --udp\t\t\tCapture UDP Packets\n"
              << "  --arp\t\t\tCapture ARP Packets\n"
              << "  --icmp4\t\t\tCapture ICMPv4 Packets\n"
              << "  --icmp6\t\t\tCapture ICMPv6 Packets\n"
              << "  --igmp\t\t\tCapture IGMP Packets\n"
              << "  --mld\t\t\tCapture MLD Packets\n"
              << "  --ndp\t\t\tCapture NDP Packets\n"
              << "  -n num\t\t\tNumber of Packets to Capture\n";
}

std::string SnifferConfig::generateFilter() const 
{
    bool first = true;
    std::string filter;

    std::vector<Protocol> protocols = {
        {"tcp", tcp},
        {"udp", udp},
        {"arp",arp},
        {"icmp", icmp4},
        {"icmp6", icmp6},
        {"igmp", igmp},
        {"mld", mld},
        {"ndp", ndp}
    };

    if (numOfProtocols == 0) {
        return "";
    }
    else if(numOfProtocols == 1)
    {
        if (tcp)    // Vyresit porty
            filter += "tcp";
        else if (udp)
            filter += "udp";
        else if (arp)
            filter += "arp";
        else if (icmp4)
            filter += "icmp";
        else if (icmp6)
            filter += "icmp6";
        else if (igmp)
            filter += "igmp";
        else if (mld)
            filter += "mld";
        else if (ndp)
            filter += "ndp";
    }
    else 
    {

        // Store The Active Protocols Into Filter
        for (const auto& proto : protocols) 
        {
            // Protocol Was Defined In Program Argument
            if (proto.isActive) 
            {
                
                if (true == first)
                {
                    if ((proto.name == "tcp" || proto.name == "udp")) 
                    {
                        filter += " port " + std::to_string(port);
                    }
                    else 
                    {
                        // Nechybi tu mezery? 
                        filter += proto.name;
                    }
                    first = false;
                }
                else 
                {
                    if ((proto.name == "tcp" || proto.name == "udp")) 
                    {
                        filter += " port " + std::to_string(port);
                    }
                    else 
                    {
                        filter += " or " + proto.name;
                    }
                }
            
            }
        }
    }
}

/// Method to Serialize Sniffer Configuration Into Filter