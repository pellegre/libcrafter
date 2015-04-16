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

#include "../Crafter.h"
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
		bool keep_going;

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

	/* Function for each thread */
	void* ARPSpoofRequest(void* thread_arg);
	void ARPNormalRequest(void* thread_arg);

	void* ARPSpoofReply(void* thread_arg);
	void ARPNormalReply(void* thread_arg);

}

#endif /* ARPSPOOFING_H_ */
