/******************************
 *  Project:        IPK Project 2 - Packet Sniffer
 *  File Name:      SnifferConfig.hpp
 *  Author:         Tomas Dolak
 *  Date:           11.04.2024
 *  Description:    Implements Parsing Sniffer Configuration.
 *
 * ****************************/

/******************************
 *  @package        IPK Project 2 - Packet Sniffer
 *  @file           SnifferConfig.hpp
 *  @author         Tomas Dolak
 *  @date           11.04.2024
 *  @brief          Implements Parsing Sniffer Configuration.
 * ****************************/

#ifndef MACROS_HPP
#define MACROS_HPP
/************************************************/
/*             Macro Definitions                */
/************************************************/
constexpr int JUST_INTERFACE = 1;
constexpr int CORRECT = 0;
constexpr int ERROR = -2;

/************************************************/
/*             NDP Packet Types                 */
/************************************************/
/**
 * @brief   Router Solicitation - It is Used During Device Initialization to Quickly Get Information About the Router, 
 *          Instead of Waiting for Regular Router Advertisement Messages.
*/
constexpr int ROUTER_SOLICITATION = 133;
/**
 * @brief   Router Advertisement - This Message Helps Configure Guests on the Network Automatically and Informs them of Network Parameters
 *          Such as Available Prefixes and MTU
*/
constexpr int ROUTER_ADVERTISEMENT = 134;
/**
 * @brief   Neighbor Solicitation - When a Device Needs to Find Out the Physical Address of a Device on the Same Link (Network),
 *          it Uses 'Neighbor Solicitation'. It is Also Used to Verify That the Neighbor Still Exists and is Reachable
*/
constexpr int NEIGHBOR_SOLICITATION = 135;
/**
 * @brief   Neighbor Advertisement - It Responds to Neighbor Solicitation Queries, Refreshes Neighbor Cache Information, 
 *          and Can Also Unsolicitedly Report Changes in Link-Layer Address.
 */
constexpr int NEIGHBOR_ADVERTISEMENT = 136;
/**
 * @brief   Redirect - This Message is Used in Environments Where There May be a Change in Topology or When a Router Determines,
 *          That There is a More Efficient Route to Route Traffic to Improve Overall Network Performance.
 */
constexpr int REDIRECT = 137;

/************************************************/
/*             MLD Packet Types                 */
/************************************************/

/**
 * @brief
*/
constexpr int MLDv1QUERY = 130;
/**
 * @brief
*/
constexpr int MLDv1REPORT = 131;
/**
 * @brief
*/
constexpr int MLDv1DONE = 132;
/**
 * @brief
*/
constexpr int MLDv2REPORT = 143;

#endif // MACROS_HPP