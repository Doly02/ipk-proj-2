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
#include "../include/macros.hpp"
/************************************************/
/*               Class Methods                  */
/************************************************/

SnifferConfig::SnifferConfig()
    : port(-1),
      tcp(false),
      udp(false),
      arp(false),
      icmp4(false),
      icmp6(false),
      igmp(false),
      ndp(false),
      portSource(false),
      portDestination(false),
      numOfProtocols(0),
      interface(""),
      mld(false),
      num(1)
{}

SnifferConfig::~SnifferConfig() {}


int SnifferConfig::parseArguments(int argc, char *argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) { // Make sure we aren't at the end of argv!
                interface = argv[++i]; // Increment 'i' so we don't get the argument as the next loop iteration
            }
            else {
                interface = "";
                return 1;
            }
        } else if (arg == "-t" || arg == "--tcp") {
            tcp = true;
            numOfProtocols++;
        } else if (arg == "-u" || arg == "--udp") {
            udp = true;
            numOfProtocols++;
        } else if (arg == "-p") {
            if (i + 1 < argc) { // Check for the next argument to be a port number
                port = std::stoi(argv[++i]);
                portSource = true;
                portDestination = true;
            }
        } else if (arg == "--port-source") {
            if (i + 1 < argc) {
                port = std::stoi(argv[++i]);
                portSource = true;
            }
        } else if (arg == "--port-destination") {
            if (i + 1 < argc) {
                port = std::stoi(argv[++i]);
                portDestination = true;
            }
        } else if (arg == "-n") {
            if (i + 1 < argc) {
                num = std::stoi(argv[++i]);
            }
        }
        else if (arg == "--arp") {
            arp = true;
            numOfProtocols++;
        }
        else if (arg == "--icmp4") {
            icmp4 = true;
            numOfProtocols++;
        }
        else if (arg == "--icmp6") {
            icmp6 = true;
            numOfProtocols++;
        }
        else if (arg == "--igmp") {
            igmp = true;
            numOfProtocols++;
        }
        else if (arg == "--mld") {
            mld = true;
            numOfProtocols++;
        }
        else if (arg == "--ndp") {
            ndp = true;
            numOfProtocols++;
        }
        else if (arg == "--help") {
            printUsage();
            exit(0);
        }
        else {
            fprintf(stderr, "Unknown Program Parameter\n");
            exit(ERROR);
        }
    }
    return 0;
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
        {
            if (portSource && portDestination)
                filter += "(tcp and port " + std::to_string(port)+ ")";
            else if (portSource)
                filter += "(tcp and src port " + std::to_string(port)+ ")";
            else if (portDestination)
                filter += "(tcp and dst port " + std::to_string(port)+ ")";
            else
                filter += "tcp";
        }
        else if (udp)
        {
            if (portSource && portDestination)
                filter += "(udp and port " + std::to_string(port)+ ")";
            else if (portSource)
                filter += "(udp and src port " + std::to_string(port)+ ")";
            else if (portDestination)
                filter += "(udp and dst port " + std::to_string(port)+ ")";
            else
                filter += "udp";
        }
        else if (arp)
            filter += "arp";
        else if (icmp4)
            filter += "icmp";
        else if (icmp6)
            filter += "icmp6 && (ip6[40] == 128 || ip6[40] == 129)";
        else if (igmp)
            filter += "igmp";
        else if (mld)
            filter += "(icmp6 and (ip6[40] == 130 or ip6[40] == 131 or ip6[40] == 132 or ip6[40] == 143))";
        else if (ndp)
            filter += "ip6 proto 58 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137)";
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
                    if ((proto.name == "tcp" || proto.name == "udp") && port != -1) 
                    {

                    if (portSource && portDestination)
                    {
                        filter += "(" + proto.name + " and port " + std::to_string(port) + ")";
                    }
                    else if (portSource)
                            filter += "(" + proto.name + " and src port " + std::to_string(port) + ")";
                        else if (portDestination)
                            filter += "(" + proto.name + " and dst port " + std::to_string(port) + ")";
                    }
                    else if (proto.name == "icmp6")
                    {
                        filter += "(" + proto.name + " && (ip6[40] == 128 || ip6[40] == 129))";
                    }
                    else if (proto.name == "mld")
                    {
                        filter += "(icmp6 and (icmp6[0] == 135 or icmp6[0] == 136))";
                    }
                    else if (proto.name == "ndp")
                    {
                        filter += "ip6 proto 58 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137)";
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
                    if ((proto.name == "tcp" || proto.name == "udp") && port != -1) 
                    {
                        if (portSource && portDestination)
                        {
                            filter += " or (" + proto.name + " and port " + std::to_string(port) + ")";
                        }
                        else if (portSource)
                            filter += " or (" + proto.name + " and src port " + std::to_string(port) + ")";
                        else if (portDestination)
                            filter += " or ()" + proto.name + " and dst port " + std::to_string(port) + ")";
                    }
                    else if (proto.name == "icmp6")
                    {
                        filter += " or (" + proto.name + " && (ip6[40] == 128 || ip6[40] == 129))";
                    }
                    else if (proto.name == "mld")
                    {
                        filter += " or (icmp6 && (ip6[40] == 130 || ip6[40] == 131 || ip6[40] == 132 || ip6[40] == 143))";
                    }
                    else if (proto.name == "ndp")
                    {
                        filter += " or (ip6 proto 58 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137))";
                    }
                    else 
                    {
                        filter += " or " + proto.name;
                    }
                }
            
            }
        }
    }
    return filter;
}

/// Method to Serialize Sniffer Configuration Into Filter