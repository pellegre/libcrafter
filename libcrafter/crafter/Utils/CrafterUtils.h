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


#ifndef CRAFTERUTILS_H_
#define CRAFTERUTILS_H_

#include <iostream>
#include <string>
#include <set>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "PacketContainer.h"

namespace Crafter {

	/* Get interface hardware address */
	std::string GetMyMAC(const std::string& iface = "");
	/* Get MAC using an ARP request */
	const std::string GetMAC(const std::string& IPAddress, const std::string& iface = "");

	/* Get interface IP address */
	std::string GetMyIP(const std::string& iface = "");
	std::string GetMyIPv6(const std::string& iface = "");

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

	/* ---------------- Send an Receive functions (wrappers for backward compatibility) -------------- */

	/* Dump packet container on a pcap file */
	void DumpPcap(const std::string& filename, PacketContainer* pck_container);

	/* Read a pcap file */
	PacketContainer* ReadPcap(const std::string& filename, const std::string& filter = "");

	/* Send and Receive a container of packet - Multithreading */
	PacketContainer* SendRecv(PacketContainer* pck_container, const std::string& iface = "",
			                  int num_threads = 16, double timeout = 1, int retry = 3);

	/* Send a container of packet - Multithreading */
	void Send(PacketContainer* pck_container, const std::string& iface = "", int num_threads = 16);

	/* --------------- Search layers by protocols -------------- */

	ARP* GetARP(const Packet& packet);
	Ethernet* GetEthernet(const Packet& packet);
	ICMP* GetICMP(const Packet& packet);
	IPLayer* GetIPLayer(const Packet& packet);
	IP* GetIP(const Packet& packet);
	IPv6* GetIPv6(const Packet& packet);
	TCP* GetTCP(const Packet& packet);
	UDP* GetUDP(const Packet& packet);

	RawLayer* GetRawLayer(const Packet& packet);

	/* Craft the layer */
	void CraftLayer(Layer* layer);

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
