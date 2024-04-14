/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      IPv4packetSniffer.cpp
 *  Author:         Tomas Dolak
 *  Date:           11.04.2024
 *  Description:    Implements Parsing Sniffer Configuration.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           IPv4packetSniffer.cpp
 *  @author         Tomas Dolak
 *  @date           11.04.2024
 *  @brief          Implements Parsing Sniffer Configuration.
 * ****************************/

/************************************************/
/*                  Libraries                   */
/************************************************/
#include <pcap.h>
#include <iostream>
#include "../include/NetworkInterfacePrinter.hpp"
/************************************************/
/*               Class Methods                  */
/************************************************/

void NetworkInterfacePrinter::printAvailableInterfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    int status = pcap_findalldevs(&alldevs, errbuf);

    if (status != 0) {
        std::cerr << "pcap_findalldevs() failed: " << errbuf << std::endl;
        return;
    }

    for (device = alldevs; device != nullptr; device = device->next) {
        std::cout << device->name << std::endl;
    }

    pcap_freealldevs(alldevs);
}