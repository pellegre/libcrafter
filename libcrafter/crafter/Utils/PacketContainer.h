/*
 * PacketContainer.h
 *
 *  Created on: Jun 7, 2012
 *      Author: larry
 */

#ifndef PACKETCONTAINER_H_
#define PACKETCONTAINER_H_

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>

#include "../Crafter.h"

namespace Crafter {

	template<typename T>
	T fromString(const std::string& str) {
		std::istringstream s(str);
		T t;
		s >> t;
		return t;
	}

	template<typename T>
	std::string toString(const T& t) {
		std::ostringstream s;
		s << t;
		return s.str();
	}

	class PacketContainer : public std::vector<Packet*> {

		/* Sender functions */
		void SendMultiThread(const std::string& iface, int num_threads);
		void SendLoop(const std::string& iface);

		/* Sender and matcher functions */
		PacketContainer* SendRecvMultiThread(const std::string& iface, double timeout, int retry, int num_threads);
		PacketContainer* SendRecvLoop(const std::string& iface, double timeout, int retry);

	public:

		PacketContainer() { /* */ };
		PacketContainer(size_t n) : std::vector<Packet*>(n) { /* */ };

		/* Copy constructor */
		PacketContainer(const PacketContainer& cpy);
		/* Assignment operator */
		PacketContainer& operator=(const PacketContainer& right);

		/* Send the packets */
		void Send(const std::string& iface = "", int num_threads = 0);

		/* Send and Receive the container  */
		PacketContainer* SendRecv(const std::string& iface = "", double timeout = 1, int retry = 3, int num_threads = 0);

		/* Dump packet container on a pcap file */
		void DumpPcap(const std::string& filename);
		/* Read a pcap file */
		void ReadPcap(const std::string& filename, const std::string& filter = "");

		/*
		 * Delete all the pointer and clear the container
		 * This function should be used only in case the packets were allocated on the heap
		 */
		void ClearPackets();

		virtual ~PacketContainer() { /* */ };

	};

}

#endif /* PACKETCONTAINER_H_ */
