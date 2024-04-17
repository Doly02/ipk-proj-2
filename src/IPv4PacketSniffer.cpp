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
#include "../include/IPv4PacketSniffer.hpp"
#include <iostream>
/************************************************/
/*               Class Methods                  */
/************************************************/

/**
 * @brief Construct a new IPv4PacketSniffer::IPv4PacketSniffer object
 * 
 * @param interfaceName Interface on which the sniffer will be listening 
 * @param filter filter expression
 * @param maxPackets Maximum number of packets to capture
*/
IPv4PacketSniffer::IPv4PacketSniffer(const std::string& interfaceName, const std::string& filter, int maxPackets)
    :   interfaceName(interfaceName), 
        filterExpression(filter), 
        maxPackets(maxPackets), 
        deviceHandle(nullptr) {
        setupDevice(); // Setup device
}
/**
 * @brief Destruct a new IPv4PacketSniffer::IPv4PacketSniffer object
 * 
*/
IPv4PacketSniffer::~IPv4PacketSniffer() {
    if (deviceHandle) {
        pcap_close(deviceHandle);  // Close pcap Handle
    }
}


void IPv4PacketSniffer::processMLDPacket(const u_char *packet, const struct pcap_pkthdr *header) {
    //const struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    const struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    printf("ICMP6 type: %d\n", icmp6->icmp6_type);
    if (icmp6->icmp6_type == 130 || icmp6->icmp6_type == 131 || icmp6->icmp6_type == 132 || icmp6->icmp6_type == 143) {
        std::cout << "MLD message detected, type: " << static_cast<int>(icmp6->icmp6_type) << std::endl;
        //actNumMldPackets++;
        //if (actNumMldPackets >= maxPackets) {
        //    pcap_breakloop(deviceHandle);
        //}
    }
    else if (header)
        return;
}


/**
 * @brief Setups the device for capturing packets
 * 
*/
void IPv4PacketSniffer::setupDevice() {
    // Open Device for Packet Capture With Set Buffer Size And With TimeOut
    printf("Interface: %s\n", interfaceName.c_str());
    deviceHandle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (deviceHandle == nullptr) {
        throw std::runtime_error("pcap_open_live failed: " + std::string(errbuf));  // If Fails Throw Exception
    }
    applyFilter();  // Apply The Filter
}

/**
 * @brief Applies The Filter From An Argument As pcap Library Filter
 * 
*/
void IPv4PacketSniffer::applyFilter() {
    struct bpf_program fp;  // Struct For Compiled Filter
    bpf_u_int32 net = 0;    // 'net' Used In Case When Net Is Not Needed

    printf("Filter: %s\n", filterExpression.c_str());
    // Compile The Filter For Device
    if (pcap_compile(deviceHandle, &fp, filterExpression.c_str(), 0, net) == -1) {
        throw std::runtime_error("pcap_compile failed: " + std::string(pcap_geterr(deviceHandle)));
    }

    // Apply The Filter On The Device 
    if (pcap_setfilter(deviceHandle, &fp) == -1) {
        pcap_freecode(&fp);  // Deallocate The Resources For Filter
        throw std::runtime_error("pcap_setfilter failed: " + std::string(pcap_geterr(deviceHandle)));
    }

    pcap_freecode(&fp);  // Deallocated Resources After The Filter's Application
}

/**
 * @brief Starts The Packet Capture on Device With Applied Filter
 * 
*/
void IPv4PacketSniffer::startCapture() {

    // Call of pcap_loop for Continual Packet Capturing According to The Filter and Number of Packets
    pcap_loop(deviceHandle, maxPackets, [](u_char *, const struct pcap_pkthdr *header, const u_char *packet) {
    print_packet(packet, header);
    }, nullptr);
}
