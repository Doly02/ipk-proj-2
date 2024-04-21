# IPK Project 2: IPK Network sniffer
- Author: Tomáš Dolák 
- Login: [xdolak09](https://www.vut.cz/lide/tomas-dolak-247220)
- Email: <xdolak09@stud.fit.vutbr.cz>


The goal of this second project in the subject of communication and site was to create a network sniffer. The assignment can be viewed [here](https://git.fit.vutbr.cz/NESFIT/IPK-Projects-2024/src/branch/master/Project%202/zeta).

## Table of contents
- [Requirements](#requirements)
- [Installation](#installation)
- [Project organization](#project-organization)


## Requirements
To build and run `ipk-sniffer`, you will need the following:

### Compiler
- **Clang++** with support for **C++17** standard. This project uses specific compiler flags to enforce code quality and standards. Make sure your compiler version supports `-std=c++17` along with the flags `-Wall -Wextra -Werror -Wshadow -Wnon-virtual-dtor -pedantic`.

### Libraries
- **Google Test (gtest)**: Required for compiling and running the unit tests. Ensure you have Google Test installed on your system as it uses `-lgtest -lgtest_main -pthread` flags for linking.

- **python scapy**: Scapy is a packet manipulation tool for computer networks. Library is required for run `python3` script which checks that all packet subsets that need to be captured are captured by the sniffer.

The `Scapy` Library can be installed on Ubuntu by command:
`pip install scapy`

### Build tools
- **Make**: This project uses a `Makefile` for easy building and testing. Ensure you have Make installed on your system.

### Operating system
- The Makefile and C++ code were designed with Unix-like environments in mind (Linux, MacOS). While it may be possible to compile and run the project on Windows, using a Unix-like environment (or WSL for Windows users) is recommended.

## Installation
1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. Run `make` to build the client application. This will create the `ipk24chat-client` executable.
4. (Optional) Run `make test` to build and run the unit tests. Ensure you have Google Test installed.

Please refer to the Makefile for additional targets and commands.

## Project organization 
```
ipk-proj-1/
│
├── include/                # Header files for class declarations.
│
├── src/                    # Source files containing class definitions and main application logic.
│
├── test/                   # Test files
│   ├── mld_test/           # Python scripts based on scapy library, used to send MLD packets.
│   │   
│   │── prep_packet.py      # Script with functions that prepare packets to be forwarded.
│   │   
│   └── sniff_test.py       # The main test script, turns on the sniffer, sends the packet and checks the output.
│
├── doc/                    # Documentation files and resources
│   └── pics/               # Directory of pictures used in README.md
│
├── Makefile                # Makefile for compiling the project
│
└── README.md               # Overview and documentation for the project
```
