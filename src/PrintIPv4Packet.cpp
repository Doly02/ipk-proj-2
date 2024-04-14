/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      PrintIPv4Packet.cpp
 *  Author:         Tomas Dolak
 *  Date:           14.04.2024
 *  Description:    Implements Functions For IPv4 Packet Information Printing.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           PrintIPv4Packet.cpp
 *  @author         Tomas Dolak
 *  @date           14.04.2024
 *  @brief          Implements Functions For IPv4 Packet Information Printing.
 * ****************************/

/************************************************/
/*                  Libraries                   */
/************************************************/
#include "../include/PrintIPv4Packet.hpp"
/************************************************/
/*           Function Implementation            */
/************************************************/
std::string format_mac(const u_char* mac) {
    std::ostringstream stream;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(mac[i]);
        if (i < ETHER_ADDR_LEN - 1) stream << ":";
    }
    return stream.str();
}

std::string format_ip(in_addr ip_addr) {
    return inet_ntoa(ip_addr);
}

std::string format_timestamp(const struct timeval& tv) {
    std::time_t nowtime = tv.tv_sec;
    struct tm *nowtm = std::gmtime(&nowtime);
    char tmbuf[64], buf[64];
    std::strftime(tmbuf, sizeof tmbuf, "%Y-%m-%dT%H:%M:%S", nowtm);
    std::snprintf(buf, sizeof buf, "%s.%06ld+00:00", tmbuf, (long)tv.tv_usec);
    return buf;
}

std::string format_hex(const u_char *data, size_t length) {
    std::ostringstream stream;
    for (size_t i = 0; i < length; i++) {
        stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < length)
            stream << std::endl << "0x" << std::setw(4) << std::setfill('0') << i + 1 << ": ";
        else
            stream << " ";
    }
    return stream.str();
}

void print_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    std::cout << "timestamp: " << format_timestamp(header->ts) << std::endl;
    std::cout << "src MAC: " << format_mac(eth_header->ether_shost) << std::endl;
    std::cout << "dst MAC: " << format_mac(eth_header->ether_dhost) << std::endl;
    std::cout << "frame length: " << header->len << " bytes" << std::endl;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
        std::cout << "src IP: " << format_ip(ip_hdr->ip_src) << std::endl;
        std::cout << "dst IP: " << format_ip(ip_hdr->ip_dst) << std::endl;

        switch (ip_hdr->ip_p) {
            case IPPROTO_TCP: {
                struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                std::cout << "src port: " << ntohs(tcp_hdr->th_sport) << std::endl;
                std::cout << "dst port: " << ntohs(tcp_hdr->th_dport) << std::endl;
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr *udp_hdr = (struct udphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                std::cout << "src port: " << ntohs(udp_hdr->uh_sport) << std::endl;
                std::cout << "dst port: " << ntohs(udp_hdr->uh_dport) << std::endl;
                break;
            }
            case IPPROTO_ICMP: {
                struct icmphdr *icmp_hdr = (struct icmphdr *)((u_char *)ip_hdr + (ip_hdr->ip_hl << 2));
                std::cout << "ICMP type: " << static_cast<int>(icmp_hdr->type) << std::endl;
                std::cout << "ICMP code: " << static_cast<int>(icmp_hdr->code) << std::endl;
                break;
            }
        }
        std::cout << std::endl << "0x0000: " << format_hex(packet, header->caplen) << std::endl;
    }
}