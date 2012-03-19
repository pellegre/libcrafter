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


#ifndef PACKET_H_
#define PACKET_H_
#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <pcap.h>
#include <libnet.h>

#include "Layer.h"
#include "RawLayer.h"

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

		/* Craft data from the layer pushed into the stack */
		void Craft();

	public:
		/* Initialize and clean */
		friend void InitCrafter();
		friend void CleanCrafter();

		/* Constructor */
		Packet() : raw_data(0), bytes_size(0)  { /* */ };

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
		void PacketFromIP(const byte* data);
		void PacketFromEthernet(const byte* data, size_t length);

		/* Construct packet a raw layer */
		void PacketFromIP(const RawLayer& data);
		void PacketFromEthernet(const RawLayer& data);

		/* Put raw data on array and resturns the number of bytes copied */
		size_t GetData(byte* raw_ptr) const;

		/* Push a Layer into the stack */
		void PushLayer(const Layer& layer);
		/* Pop and destroy the layer on top */
		void PopLayer();

		/* Get size of the packet in bytes */
		size_t GetSize() const { return bytes_size; };

		/* Put a packet into the wire */
		void Send(const std::string& iface = "");

		/* Send a packet and try to match the answer */
		Packet* SendRecv(const std::string& iface = "", int timeout = 5, int retry = 3, const std::string& user_filter = " ");

		/* Put a packet into the wire trought a socket */
		void RawSocketSend(int sd, const std::string& iface = "");

		/* Send a packet and match the answer */
		Packet* RawSocketSendRecv(int sd, const std::string& iface = "", int timeout = 5, int retry = 3, const std::string& user_filter = " ");

		/* Print each layer of the packet */
		void Print() const;

		/* Print Data as a raw string */
		void RawString();

		/* Hexdump the data */
		void HexDump();

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
