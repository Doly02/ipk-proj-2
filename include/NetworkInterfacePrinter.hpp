#ifndef NETWORK_INTERFACE_PRINTER_H
#define NETWORK_INTERFACE_PRINTER_H
/************************************************/
/*                  Libraries                   */
/************************************************/
#include <pcap.h>
#include <iostream>
/************************************************/
/*               Class Definition               */
/************************************************/
class NetworkInterfacePrinter {
public:
    void printAvailableInterfaces();
};

#endif // NETWORK_INTERFACE_PRINTER_H