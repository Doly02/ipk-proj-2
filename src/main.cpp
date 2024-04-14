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
#include "../include/SnifferConfig.hpp"
#include "../include/macros.hpp"
#include "../include/NetworkInterfacePrinter.hpp"
/************************************************/
/*               Main                           */
/************************************************/
int main(int argc, char *argv[]) {
    
    int retVal = 0;
    SnifferConfig config;
    retVal = config.parseArguments(argc, argv);
    if (1 == retVal) {
        NetworkInterfacePrinter printer;
        printer.printAvailableInterfaces();
        return 0;
    }
    else if (retVal != 0) {
        return retVal;
    }
    // Continue
    std::string filter = config.generateFilter();
    return 0;
}