/*
 * InitCrafter.cpp
 *
 *  Created on: Jun 19, 2012
 *      Author: larry
 */
#include "InitCrafter.h"
#include "Crafter.h"
#include "Utils/CrafterUtils.h"

void Crafter::InitCrafter() {

        IPOptionSSRR ipssrr_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&ipssrr_dummy);

        IPOptionRR iprr_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&iprr_dummy);

        IPOptionLSRR iplsrr_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&iplsrr_dummy);

        IPOptionTraceroute iptrace_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&iptrace_dummy);

        IPOptionPad ippadopt_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&ippadopt_dummy);

        IPOption ipopt_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&ipopt_dummy);

        IP ip_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&ip_dummy);

        IPv6 ipv6_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&ipv6_dummy);

        UDP udp_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&udp_dummy);

        TCP tcp_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&tcp_dummy);

        TCPOption opt_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&opt_dummy);

        TCPOptionMaxSegSize optmss_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&optmss_dummy);

        TCPOptionTimestamp optts_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&optts_dummy);

        TCPOptionPad optpad_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&optpad_dummy);

        ICMP icmp_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&icmp_dummy);

        ICMPExtension icmp_extension_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&icmp_extension_dummy);

        ICMPExtensionMPLS icmp_extension_mpls_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&icmp_extension_mpls_dummy);

        ICMPExtensionObject icmp_extension_object_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&icmp_extension_object_dummy);

        Ethernet ether_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&ether_dummy);

        SLL sll_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&sll_dummy);

        ARP arp_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&arp_dummy);

        RawLayer raw_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&raw_dummy);

        DNS dns_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&dns_dummy);

        DHCP dhcp_dummy;
        /* Register the protocol, this is executed only once */
        Protocol::AccessFactory()->Register(&dhcp_dummy);

        /* Initialize seed of RNG */
        srand(time(NULL));

        /* Put verbose mode as default */
        ShowWarnings = 1;

        /* Initialize Mutex variables */
        Packet::InitMutex();
        Sniffer::InitMutex();

}

void Crafter::CleanCrafter() {
        /* Destroy Mutex Varibles */
        Packet::DestroyMutex();
        Sniffer::DestroyMutex();
}



