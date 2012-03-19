/*
Copyright (C) 2012 Pellegrino E.

This file is part of libcrafter

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/


#ifndef ARPSPOOFING_H_
#define ARPSPOOFING_H_

#include <iostream>
#include <string>
#include <set>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "Crafter.h"
#include "CrafterUtils.h"

namespace Crafter {
	/* ARP Context - All private Members*/
	class ARPContext {
		/* Type of spoofing */
		static const byte Request = 0;
		static const byte Reply = 1;

		/* Friend functions */
		friend ARPContext* ARPSpoofingRequest(const std::string& net_target, const std::string& net_victim, const std::string& iface);
		friend ARPContext* ARPSpoofingReply(const std::string& net_target, const std::string& net_victim, const std::string& iface);

		friend void CleanARPContext(ARPContext* arp_context);
		friend void PrintARPContext(const ARPContext& context);
		friend void BlockARP(ARPContext* context);

		friend void* ARPSpoofRequest(void* thread_arg);
		friend void ARPNormalRequest(void* thread_arg);

		friend void* ARPSpoofReply(void* thread_arg);
		friend void ARPNormalReply(void* thread_arg);

		/* Thread ID of the thread that is doing the spoofing */
		pthread_t tid;

		/* Attacker's MAC Address */
		std::string AttackerMAC;

		/* Interface for send the arp packets */
		std::string iface;

		/* Target's IP and MAC address couples */
		std::vector<std::string>* TargetIPs;
		std::vector<std::string>* TargetMACs;

		/* Victim's IP and MAC address couples */
		std::vector<std::string>* VictimIPs;
		std::vector<std::string>* VictimMACs;

		/* Pointer to a packet container */
		PacketContainer* arp_packets;

		/* Type of the spoofing (request or replies) */
		byte type;

		/* Perform Sanity check */
		void SanityCheck();
	};

	/* Print information on the ARP spoof context */
	void PrintARPContext(const ARPContext& context);

	/* ARP multithreading function */
	ARPContext* ARPSpoofingRequest(const std::string& net_target, const std::string& net_victim, const std::string& iface="");
	ARPContext* ARPSpoofingReply(const std::string& net_target, const std::string& net_victim, const std::string& iface="");

	/* Block ARP Spoofing */
	void BlockARP(ARPContext* context);

	/* Shutdown cleany the ARPSpoofer */
	void CleanARPContext(ARPContext* arp_context);

	/* Get MAC using an ARP request */
	const std::string GetMAC(const std::string& IPAddress, const std::string& iface = "");

	/* Function for each thread */
	void* ARPSpoofRequest(void* thread_arg);
	void ARPNormalRequest(void* thread_arg);

	void* ARPSpoofReply(void* thread_arg);
	void ARPNormalReply(void* thread_arg);

}

#endif /* ARPSPOOFING_H_ */
