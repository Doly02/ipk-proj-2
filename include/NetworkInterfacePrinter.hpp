#ifndef NETWORK_INTERFACE_PRINTER_H
#define NETWORK_INTERFACE_PRINTER_H

#include <pcap.h>
#include <iostream>

class NetworkInterfacePrinter {
public:
    void printAvailableInterfaces();
};

#endif // NETWORK_INTERFACE_PRINTER_H