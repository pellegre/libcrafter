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


#ifndef CRAFTERUTILS_H_
#define CRAFTERUTILS_H_

#include <iostream>
#include <string>
#include <set>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>

namespace Crafter {

	/* Get interface hardware address */
	std::string GetMyMAC(const std::string& iface = "");

	/* Get interface IP address */
	std::string GetMyIP(const std::string& iface = "");

	/* Initialize and clean */
	void InitCrafter();
	void CleanCrafter();

	/* Parse an IP in nmap style */
	std::vector<std::string>* ParseIP(const std::string& argv);

	/* Parse an octect in nmap style */
	std::vector<int>* ParseNumbers(const std::string& argv);

	/* Put port on a string */
	std::string StrPort(short_word port_number);

	/* Cast layers to protocols */
	template<class T>
	T* GetLayer(Layer* layer) {
		return dynamic_cast<T*>(layer);
	}

	/* ---------------- Send an Receive functions -------------- */

	typedef std::vector<Packet*> PacketContainer;

	/* Send and Receive a container of packet - Multithreading */
	PacketContainer* SendRecv(PacketContainer* PacketContainer, const std::string& iface = "",
			                        int num_threads = 16, int timeout = 5, int retry = 3);

	/* Send a container of packet - Multithreading */
	void Send(PacketContainer* PacketContainer, const std::string& iface = "", int num_threads = 16);

	/* --------------- Search layers by protocols -------------- */

	ARP* GetARP(const Packet& packet);
	Ethernet* GetEthernet(const Packet& packet);
	ICMP* GetICMP(const Packet& packet);
	IP* GetIP(const Packet& packet);
	TCP* GetTCP(const Packet& packet);
	UDP* GetUDP(const Packet& packet);
	RawLayer* GetRawLayer(const Packet& packet);

	/* ------------------- Some operators ---------------------- */

	const Packet operator/(const Layer& left, const Layer& right);

}

/* ARP stuff */
#include "ARPSpoofing.h"

/* The sniffer */
#include "Sniffer.h"

/* Some TCP tools */
#include "TCPConnection.h"

#endif /* CRAFTERUTILS_H_ */
