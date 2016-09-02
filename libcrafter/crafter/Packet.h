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

#include "Crafter.h"
#include "Utils/RawSocket.h"

namespace Crafter {

	typedef std::vector<Layer*> LayerStack;

	class Packet {

		/* Stack of layers */
		std::vector<Layer*> Stack;
		/* Raw data of the packet in form of a payload */
		byte* raw_data;
		/* Size in bytes of the packet */
		size_t bytes_size;

		/* Pre-Crafted flag. This flag is set when an user wnats to handle the crafting by himself */
		byte pre_crafted;

		/* Packet time stamp */
		timeval ts;

		/* Mutex variable */
		static pthread_mutex_t mutex_compile;

		/* Manage static Mutex variable used for multithreading */
		static void InitMutex();
		static void DestroyMutex();

		/* Construct the packet from a layer to the top */
		void GetFromLayer(const byte* data, size_t length, short_word proto_id);

		/* Craft data from the layer pushed into the stack */
		void Craft();

		/* Send the packet over the wire */
		int ToWire(int raw, word current_id, byte *raw_data, size_t bytes_size);

	public:
		/* Initialize and clean */
		friend void InitCrafter();
		friend void CleanCrafter();

		/* Packet handler function */
		typedef void ((*PacketHandler)(Packet*,void*));

		/* Constructor */
		Packet() : raw_data(0), bytes_size(0), pre_crafted(0) { ts.tv_sec = 0; ts.tv_usec = 0; };
		Packet(timeval  ts) : raw_data(0), bytes_size(0), pre_crafted(0), ts(ts) { /* */ };
		Packet(const byte* data, size_t length, short_word proto_id);
		Packet(const RawLayer& data, short_word proto_id);

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

		/* Construct a packet from raw data using the layer <proto_id> as a starting point */
		void Decode(const byte* data, size_t length, short_word proto_id);
		void Decode(const RawLayer& data, short_word proto_id);

		/* Construct packet from data - SIMPLE WRAPPERS FOR BACKWARD COMPATIBILITY*/
		void PacketFromIP(const byte* data, size_t length);
		void PacketFromIPv6(const byte* data, size_t length);
		void PacketFromEthernet(const byte* data, size_t length);
		/* Packet from link layer (link_proto in the datalink type defined by libpcap) */
		void PacketFromLinkLayer(const byte* data, size_t length, int link_proto);
		/* Construct packet a raw layer */
		void PacketFromIP(const RawLayer& data);
		void PacketFromIPv6(const RawLayer& data);
		void PacketFromEthernet(const RawLayer& data);

		/* Put raw data on array and returns the number of bytes copied */
		size_t GetData(byte* raw_ptr);
		/* Get a pointer to the raw buffer inside the packet (which holds the crafted data) */
		const byte* GetRawPtr();
		/* Get a pointer to the raw buffer inside the packet (this is a const method, without crafting the data) */
		const byte* GetBuffer() const;

		/* Get time stamp */
		timeval GetTimestamp() const;
		/* Set time stamp */
		void SetTimestamp(timeval timestamp);

		/* Push a Layer into the stack */
		void PushLayer(const Layer& layer);
		void PushLayer(Layer* layer);
		/* Pop and destroy the layer on top */
		void PopLayer();

		/*
		 * Craft a packet and set the pre_crafted flag to one.
		 * When this function is called, the crafting is handled by the user.
		 */
		void PreCraft();

		/* Get size of the packet in bytes */
		size_t GetSize() const { return bytes_size; };

		/* Put a packet into the wire */
		int Send(const std::string& iface = "");

		/* Send a packet and try to match the answer */
		Packet* SendRecv(const std::string& iface = "",double timeout = 1, int retry = 3, const std::string& user_filter = " ");
		template<class Pointer>
		void SendRecvPtr(const std::string& iface, double timeout, int retry, const std::string& user_filter, Pointer& ptr);

		/*
		 * Put a packet into the wire trough a raw socket
		 * (should be a PF_INET or PF_PACKET accordingly to the type of packet crafted)
		 */
		int SocketSend(int sd);
		/* Send a packet and try to match the answer */
		Packet* SocketSendRecv(int sd, const std::string& iface = "",double timeout = 1, int retry = 3, const std::string& user_filter = " ");
		template<class Pointer>
		void SocketSendRecvPtr(int sd, const std::string& iface, double timeout, int retry, const std::string& user_filter, Pointer& ptr);
		void GetFilter(std::stringstream& out) const;

		/* Print each layer of the packet */
		void Print(std::ostream& str) const;
		void Print() const;

		/* Print Data as a raw string */
		void RawString(std::ostream& str = std::cout);

		/* Hexdump the data */
		void HexDump(std::ostream& str = std::cout);

		/* -------------- Layer Manipulation functions ------------- */

		/* Get a layer from the position on the stack */
		template<class Protocol>
		Protocol* GetLayer(size_t n) const;

		/* Get a layer of a specific type */
		template<class Protocol>
		Protocol* GetLayer() const;

		/* Get next layer of a specific type from a start point */
		template<class Protocol>
		Protocol* GetLayer(const Protocol* layer_ptr) const;

		/* Find a layer of a specific type and return a iterator to that layer */
		template<class Protocol>
		LayerStack::const_iterator Find() const;
		template<class Protocol>
		LayerStack::const_iterator Find(LayerStack::const_iterator begin) const;

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

		/* Get the numbers of layers on the stack */
		size_t GetLayerCount() const { return Stack.size(); } ;

		/* Get reference to a layer */
		Layer* operator[](size_t pos);
		const Layer* operator[](size_t pos) const;

		/* Get a packet from a subset of layer of the current packet */
		Packet SubPacket(LayerStack::const_iterator begin, LayerStack::const_iterator end) const;
		Packet SubPacket(size_t begin, size_t end) const;

		/* Destructor */
		virtual ~Packet();
	};

	template<>
	IPLayer* Packet::GetLayer<IPLayer>() const;

	template<>
	ICMPLayer* Packet::GetLayer<ICMPLayer>() const;
}

template<class Protocol>
Protocol* Crafter::Packet::GetLayer(size_t n) const {
	if (n < Stack.size())
		return dynamic_cast<Protocol*>(Stack[n]);
	else {
		Crafter::PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Packet::GetLayer(size_t n)",
		             "Layer requested out of bounds.");
		return 0;
	}
}

template<class Protocol>
Protocol* Crafter::Packet::GetLayer() const {
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = begin() ; it_layer != end() ; ++it_layer)
		if ((*it_layer)->GetID() == Protocol::PROTO)
			return dynamic_cast<Protocol*>( (*it_layer) );

	/* No requested layer, returns zero */
	return 0;
}

template<class Protocol>
Protocol* Crafter::Packet::GetLayer(const Protocol* layer_ptr) const {
	/* Get next layer on the packet */
	Crafter::Layer* next_layer = layer_ptr->GetTopLayer();

	/* Go trough each layer */
	while(next_layer) {
		if(next_layer->GetID() == Protocol::PROTO)
			return dynamic_cast<Protocol*>(next_layer);
		next_layer = next_layer->GetTopLayer();
	}

	/* Return the layer with the searched ID or a null pointer */
	return 0;
}

/* Find a layer of a specific type and return a iterator to that layer */
template<class Protocol>
Crafter::LayerStack::const_iterator Crafter::Packet::Find() const {
	LayerStack::const_iterator it_layer;
	for (it_layer = begin() ; it_layer != end() ; ++it_layer)
		if ((*it_layer)->GetID() == Protocol::PROTO) break;

	return it_layer;
}

template<class Protocol>
Crafter::LayerStack::const_iterator Crafter::Packet::Find(Crafter::LayerStack::const_iterator begin) const {
	LayerStack::const_iterator it_layer;
	for (it_layer = begin ; it_layer != end() ; ++it_layer)
		if ((*it_layer)->GetID() == Protocol::PROTO) break;

	return it_layer;
}

/* Send a packet */
template<class Pointer>
void Crafter::Packet::SendRecvPtr(const std::string& iface, double timeout, int retry, const std::string& user_filter, Pointer& ptr) {
	Packet* pck = SendRecv(iface,timeout,retry,user_filter);
	if(pck) ptr = Pointer(pck);
	else ptr = Pointer();
}

/* Send a packet with socket */
template<class Pointer>
void Crafter::Packet::SocketSendRecvPtr(int sd,const std::string& iface, double timeout, int retry, const std::string& user_filter, Pointer& ptr) {
	Packet* pck = SocketSendRecv(sd,iface,timeout,retry,user_filter);
	if(pck) ptr = Pointer(pck);
	else ptr = Pointer();
}

#endif /* PACKET_H_ */
