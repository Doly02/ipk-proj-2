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
#include "../include/Sniffer.hpp"
/************************************************/
/*                   Main                       */
/************************************************/
int main(int argc, char *argv[]) {
    
    int retVal = 0;
    SnifferConfig config;
    retVal = config.parseArguments(argc, argv);
    if (JUST_INTERFACE == retVal) {
        NetworkInterfacePrinter printer;
        printer.printAvailableInterfaces();
        return 0;
    }
    else if (retVal != CORRECT) {
        return retVal;
    }

    std::signal(SIGINT, Sniffer::handleSignal);         // Handle SIGINT Signal
    std::string filter = config.generateFilter();
    try {
        Sniffer sniffer(config.interface.c_str(), filter, config.num);
        sniffer.startCapture();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return -2;
    }
    return 0;
}