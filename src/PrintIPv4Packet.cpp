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
#include "../include/Sniffer.hpp"
/************************************************/
/*           Function Implementation            */
/************************************************/
std::string Sniffer::formatMac(const u_char* mac) {
    std::ostringstream stream;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(mac[i]);
        if (i < ETHER_ADDR_LEN - 1) stream << ":";
    }
    return stream.str();
}

std::string Sniffer::formatIp(in_addr ip_addr) {
    return inet_ntoa(ip_addr);
}

std::string Sniffer::formatTimestamp(const struct timeval& tv) {
    std::time_t nowtime = tv.tv_sec;
    struct tm *nowtm = std::gmtime(&nowtime);
    char tmbuf[64], buf[64];
    std::strftime(tmbuf, sizeof tmbuf, "%Y-%m-%dT%H:%M:%S", nowtm);
    std::snprintf(buf, sizeof buf, "%s.%06ld+00:00", tmbuf, (long)tv.tv_usec);
    return buf;
}

std::string Sniffer::formatHex(const u_char *data, size_t length) {
    std::ostringstream stream;
    std::string ascii;
    int bytes_per_line = 16;  // Standard Number of Bytes On Line

    for (size_t i = 0; i < length; ++i) {
        // On The Beggining of Every Line Print Offset 
        if (i % bytes_per_line == 0) {
            if (i != 0) {
                stream << " " << ascii; // Add ASCII Representation at The End Of The Line
                ascii.clear();
                stream << std::endl; // New Line
            }
            stream << "0x" << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
        }

        // Add Hexadecimal Value of The Byte
        stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]);

        // Build ASCII Representation For Print In The End of the Line (If Char is Unpritable Print Dot)
        ascii += std::isprint(data[i]) ? static_cast<char>(data[i]) : '.';

        // Add Space Between Bytes
        stream << " ";

        // Space Between 8th and 9th Byte In ASCII Reprezentation
        if ((i + 1) % bytes_per_line == 8) {
            ascii += " "; 
        }

    }

    // Fill The Other Part of Line If Line Does Not Includes 16 Bytes
    size_t remaining = length % bytes_per_line;
    if (remaining != 0) {
        // Add Pedding To Align ASCII Output
        int padding = (bytes_per_line - remaining) * 3;
        stream << std::string(padding, ' ');
    }
    stream << " " << ascii; // Add Last ASCII Line

    return stream.str();
}
