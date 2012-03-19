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

#include "Crafter.h"

namespace Crafter {

	/* Data for each sniffer created */
	struct SnifferData {
		/* ID of the sniffer */
		word ID;
		/* Argument for the capture function */
		void* sniffer_arg;
	};

	class Sniffer {

		/* Packet handler function */
		typedef void ((*PacketHandler)(Packet*,void*));

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
		Sniffer(const std::string& filter = "", const std::string& iface = "", PacketHandler PacketHandlerFunction = 0);

		/* Set filter */
		void SetFilter(const std::string& filter);

		/* Set device interface */
		void SetInterface(const std::string& iface );

		/* Set Packet Handler function */
		void SetPacketHandler(PacketHandler PacketHandlerFunction);

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
