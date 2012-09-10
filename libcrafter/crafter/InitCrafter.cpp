/*
Copyright (c) 2012, Esteban Pellegrino
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ESTEBAN PELLEGRINO BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "InitCrafter.h"
#include "Crafter.h"
#include "Utils/CrafterUtils.h"

void Crafter::InitCrafter() {

	NullLoopback nullloop_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&nullloop_dummy);

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

	TCPOptionSACKPermitted optsackp_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&optsackp_dummy);

	TCPOptionSACK optsack_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&optsack_dummy);

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



