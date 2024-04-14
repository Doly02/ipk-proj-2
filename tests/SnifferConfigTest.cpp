/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      SniferConfigTest.cpp
 *  Author:         Tomas Dolak
 *  Date:           11.04.2024
 *  Description:    Implements Parsing Sniffer Configuration.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           SniferConfigTest.cpp
 *  @author         Tomas Dolak
 *  @date           11.04.2024
 *  @brief          Implements Parsing Sniffer Configuration.
 * ****************************/
#include <gtest/gtest.h>
#include "../include/SnifferConfig.hpp"

class SnifferConfigTest : public ::testing::Test {
protected:
    SnifferConfig config;  // Instance of SnifferConfig to be tested

    void SetUp() override {
        // Reset or reinitialize your config before each test
        config = SnifferConfig();  // SnifferConfig has a suitable default constructor
    }

    void TearDown() override {
        // Optional: Code here will be called after each test (cleanup)
        config = SnifferConfig(); 
    }
    // Pomocná funkce pro simulaci argumentů
    void setupArguments(const std::vector<std::string>& args) {
        std::vector<char*> argv;
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.data()));
        }
        argv.push_back(nullptr);  // Add on the end nullptr
        int argc = argv.size() - 1;

        optind = 1;  // Reset optind to 1 to ensure getopt starts from the first argument
        config.parseArguments(argc, argv.data());

    }
};
/* TODO: If Not Argument Is Set, Print Interfaces!
TEST_F(SnifferConfigTest, TestNoArguments) {
    std::vector<std::string> args = {"program_name"};
    setupArguments(args);   
    ASSERT_EQ(config.generateFilter(), "ip or ip6");
}
*/

TEST_F(SnifferConfigTest, TestSingleProtocolArgument) {
    std::vector<std::string> args = {"ipk-sniffer_test", "--tcp"};
    setupArguments(args);
    ASSERT_TRUE(config.isTcp());
    ASSERT_EQ(config.generateFilter(), "tcp");
}

TEST_F(SnifferConfigTest, TestMultipleArguments) {
    std::vector<std::string> args = {"ipk-sniffer_test", "--tcp", "--udp"};
    setupArguments(args);
    ASSERT_TRUE(config.isTcp());
    ASSERT_TRUE(config.isUdp());
    ASSERT_EQ(config.generateFilter(), "tcp or udp");
}

TEST_F(SnifferConfigTest, TestWithPorts) {
    std::vector<std::string> args = {"ipk-sniffer_test", "-p", "8080", "--tcp"};
    setupArguments(args);
    ASSERT_TRUE(config.isTcp());
    ASSERT_EQ(config.getPort(), 8080);
    ASSERT_EQ(config.generateFilter(), "tcp and port 8080");
}
