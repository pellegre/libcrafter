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


#ifndef PACKET_H_
#define PACKET_H_

#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <pcap.h>

#include "Layer.h"
#include "Protocols/RawLayer.h"

typedef uint32_t word;
typedef uint8_t byte;

namespace Crafter {

typedef std::vector<Layer*> LayerStack;

	class Packet {

		/* Stack of layers */
		std::vector<Layer*> Stack;
		/* Raw data of the packet in form of a payload */
		byte* raw_data;
		/* Size in bytes of the packet */
		size_t bytes_size;

		/* Mutex variable */
		static pthread_mutex_t mutex_compile;

		/* Manage static Mutex variable used for multithreading */
		static void InitMutex();
		static void DestroyMutex();

		/* Construct the packet from the IP layer to the top */
		void GetFromIP(const byte* data, size_t length);

		/* Craft data from the layer pushed into the stack */
		void Craft();

		/* Socket descriptor management */
		int raw;
		std::string last_iface;
		word last_id;
		byte socket_open_once;

	public:
		/* Initialize and clean */
		friend void InitCrafter();
		friend void CleanCrafter();

		/* Constructor */
		Packet() : raw_data(0), bytes_size(0), last_iface(""), last_id(0), socket_open_once(0)  { /* */ };

		/* Copy Constructor */
		Packet(const Packet& copy_packet);
		Packet(const Layer& copy_layer);

		/* Assignament operator */
		Packet& operator=(const Packet& right);
		Packet& operator=(const Layer& right);

		/* Another way to push a layer */
		const Packet operator/(const Layer& right) const;
		Packet& operator/=(const Layer& right);

		/* Concatenate two packets */
		const Packet operator/(const Packet& right) const;
		Packet& operator/=(const Packet& right);

		/* Construct packet from data */
		void PacketFromIP(const byte* data, size_t length);
		void PacketFromEthernet(const byte* data, size_t length);

		/* Packet from link layer (link_proto in the datalink type defined by libpcap) */
		void PacketFromLinkLayer(const byte* data, size_t length, int link_proto);

		/* Construct packet a raw layer */
		void PacketFromIP(const RawLayer& data);
		void PacketFromEthernet(const RawLayer& data);

		/* Put raw data on array and returns the number of bytes copied */
		size_t GetData(byte* raw_ptr);
		/* Get a pointer to the raw buffer inside the packet (wich holds the crafted data) */
		const byte* GetRawPtr();

		/* Push a Layer into the stack */
		void PushLayer(const Layer& layer);
		/* Pop and destroy the layer on top */
		void PopLayer();

		/* Get size of the packet in bytes */
		size_t GetSize() const { return bytes_size; };

		/* Put a packet into the wire */
		int Send(const std::string& iface = "");

		/* Send a packet and try to match the answer */
		Packet* SendRecv(const std::string& iface = "", int timeout = 5, int retry = 3, const std::string& user_filter = " ");

		/* Put a packet into the wire trough a raw socket */
		int RawSocketSend(int sd);

		/* Put a packet into the wire trough a raw socket */
		int PacketSocketSend(int sd);

		/* Print each layer of the packet */
		void Print(std::ostream& str = std::cout) const;

		/* Print Data as a raw string */
		void RawString(std::ostream& str = std::cout);

		/* Hexdump the data */
		void HexDump(std::ostream& str = std::cout);

		/* -------------- Layer Manipulation functions ------------- */

		template<class T>
		T* GetLayer(size_t n) const;

		/* Foward Iterators */
		LayerStack::iterator begin() { return Stack.begin(); };
		LayerStack::iterator end() { return Stack.end(); };
		LayerStack::const_iterator begin() const { return Stack.begin(); };
		LayerStack::const_iterator end() const { return Stack.end(); };

		/* Reverse Iterators */
		LayerStack::reverse_iterator rbegin() { return Stack.rbegin(); };
		LayerStack::reverse_iterator rend() { return Stack.rend(); };
		LayerStack::const_reverse_iterator rbegin() const { return Stack.rbegin(); };
		LayerStack::const_reverse_iterator rend() const { return Stack.rend(); };

		/* Destructor */
		virtual ~Packet();
	};

}

template<class T>
T* Crafter::Packet::GetLayer(size_t n) const {
	if (n < Stack.size())
		return dynamic_cast<T*>(Stack[n]);
	else {
		std::cerr << "[!] ERROR: Packet Stack out of bounds! Aborting... " << std::endl;
		exit(1);
		return 0;
	}
}

#endif /* PACKET_H_ */
