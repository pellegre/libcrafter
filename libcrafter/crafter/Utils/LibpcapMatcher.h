/*
 * LibpcapMatcher.h
 *
 *  Created on: Jun 5, 2012
 *      Author: larry
 */

#ifndef LIBPCAPMATCHER_H_
#define LIBPCAPMATCHER_H_

#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>

namespace Crafter {

	class LibpcapMatcher {

		/* String that defines the device we are listening */
		std::string device;

		/* Filter */
		std::string filter;

		/* Timeout to wait for an answer */
		int timeout;

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

		/* ---------------- Functions ------------------- */

		/* This class shouldn't be copied */
		LibpcapMatcher(const LibpcapMatcher& copy);
		LibpcapMatcher& operator= (const LibpcapMatcher& other);

		/* Compile Filter */
		void CompileFilter();

	public:

		/* Constructor */
		LibpcapMatcher(const std::string& iface, int timeout);

		/* Set filter */
		void SetFilter(const std::string& filter);

		/* Set device interface */
		void SetInterface(const std::string& iface );

		/* Capture one packet and return the data */
		void Capture(uint32_t count = -1, void *user = 0);

		/* Destructor */
		virtual ~LibpcapMatcher();
	};

}

#endif /* LIBPCAPMATCHER_H_ */
