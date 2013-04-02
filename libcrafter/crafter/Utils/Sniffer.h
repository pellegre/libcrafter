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


#ifndef SNIFFER_H_
#define SNIFFER_H_

#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>

/* Define PCAP_NETMASK_UNKNOWN if not included on pcap.h */
#ifndef PCAP_NETMASK_UNKNOWN
        #define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

#include "../Crafter.h"

namespace Crafter {

	/* Data for each sniffer created */
	struct SnifferData {
		/* ID of the sniffer */
		word ID;
		/* Argument for the capture function */
		void* sniffer_arg;
		/* Type of the link layer */
		int link_type;
	};

	class Sniffer {

		/* String that defines the device we are listening */
		char* device;

		/* Filter */
		std::string filter;

		/* Sniffer ID, for global vector data */
		word ID;

		/* ID of the thread */
		pthread_t thread_id;

		/* Pointer for sniffer data on capture function */
		SnifferData* sniffer_data;

		/* -------------- Libpcap stuff ----------------- */

		/* Handle for the opened pcap session */
		pcap_t *handle;
		/* Type of link layer of the interface */
		int link_type;
		/* Pcap error messages buffer */
		char errbuf[PCAP_ERRBUF_SIZE];
		/* IP address of interface */
		bpf_u_int32 netp;
		/* Subnet mask of interface */
		bpf_u_int32 maskp;
		/* Compiled BPF filter */
		struct bpf_program fp;
		/* Flag if the thread was spawned */
		byte spawned;

		/* -------------- Static Members ---------------- */

		/* Mutex variable */
		static pthread_mutex_t mutex_compile;

		/* Class counter */
		static word counter;

		/* Manage static Mutex variable used for multithreading */
		static void InitMutex();
		static void DestroyMutex();

		/* ---------------- Functions ------------------- */

		/* This class shouldn't be copied */
		Sniffer(const Sniffer& copy);
		Sniffer& operator= (const Sniffer& other);

		/* Compile Filter */
		void CompileFilter();

	public:
		/* Initialize and clean */
		friend void InitCrafter();
		friend void CleanCrafter();

		/* Constructor */
		Sniffer(const std::string& filter = "", const std::string& iface = "", Packet::PacketHandler PacketHandlerFunction = 0);

		/* Set filter */
		void SetFilter(const std::string& filter);

		/* Set device interface */
		void SetInterface(const std::string& iface );

		/* Set Packet Handler function */
		void SetPacketHandler(Packet::PacketHandler PacketHandlerFunction);

		/* Start capturing packets */
		void Capture(uint32_t count = -1, void *user = 0);

		/* Spawn the sniffer and return immediately to the user */
		void Spawn(uint32_t count = -1, void *user = 0);

		/* Block until the spawned thread finish the work */
		void Join();

		/* Cancel a sniffer */
		void Cancel();

		/* Destructor */
		virtual ~Sniffer();
	};

	/* Data for spawning a sniffer */
	struct SpawnData {
		/* User argument */
		void* user;
		/* Packet count, for Capture argument */
		uint32_t count;
		/* Pointer to the sniffer */
		Sniffer* sniff_ptr;
	};

}

#endif /* SNIFFER_H_ */
