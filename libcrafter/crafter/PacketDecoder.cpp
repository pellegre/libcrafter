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


#include "Packet.h"
#include "Crafter.h"
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <pcap.h>

using namespace std;
using namespace Crafter;

void Packet::GetFromLayer(const byte* data, size_t length, short_word proto_id) {
	/* Create an information structure */
	Layer::ParseInfo* info = new Layer::ParseInfo;

	/* Put initial information */
	info->raw_data = data;
	info->total_size = length;
	/* Put initial layer */
	info->next_layer = Protocol::AccessFactory()->GetLayerByID(proto_id);

	while(!info->top) {
		/* Create the next layer */
		Layer* next_layer = info->next_layer;

		if(!next_layer) break;

		/* Hijack the info structure to see if the data fit into this layer */
		size_t remain = info->total_size - info->offset;

		/* Check if the data don't fit into this header */
		if(next_layer->GetSize() > remain) {
			/* We can't go further */
			if(remain) {
				RawLayer rawdata(info->raw_data + info->offset,remain);
				PushLayer(rawdata);
			}
			/* Delete the layer created */
			delete next_layer;
			/* Delete info structure */
			delete info;
			/* That's all */
			return;
		}

		next_layer->ParseData(info);

		/* Push the new layer into the packet */
		PushLayer(*next_layer);

		/* Hijack the next layer pointer if this layer is binded to some other */
		short_word next_proto = next_layer->CheckBinding();
		/* Delete the layer created */
		delete next_layer;

		if(next_proto) {
			/* It's binded */
			info->top = 0; /* Reset the top flag, some layers set the flag to one when done */
			info->next_layer = Protocol::AccessFactory()->GetLayerByID(next_proto);
		}

	}

	/* Push the remaining (if any) bytes as a raw layer */
	size_t data_length = info->total_size - info->offset;

	if(data_length) {
		/* Create a raw payload with the rest of the data */
		RawLayer raw_layer(info->raw_data + info->offset, data_length);
		PushLayer(raw_layer);
	}

	delete info;
}

void Packet::Decode(const byte* data, size_t length, short_word proto_id) {
	/* First remove bytes for the raw data */
	if (raw_data) {
		bytes_size = 0;
		delete [] raw_data;
		raw_data = 0;
	}
	/* Delete layer one by one */
	vector<Layer*>::iterator it_layer;
	for (it_layer = Stack.begin() ; it_layer != Stack.end() ; ++it_layer)
		delete (*it_layer);

	Stack.clear();

	GetFromLayer(data,length,proto_id);
}

void Packet::Decode(const RawLayer& data, short_word proto_id) {
	/* Construct the packet from the buffer */
	Decode(data.GetPayload().GetRawPointer(), data.GetSize(),proto_id);
}

/* [+] ----------- From Link layer */

/* Constructor from raw data */
void Packet::PacketFromLinkLayer(const byte* data, size_t length, int link_proto) {

	/* Next layer type (should be somewhere on the link protocol header) */
	short_word first_layer = 0;

	if(link_proto == DLT_EN10MB) {
		/* First bytes are an Ethernet Layer */
		first_layer = Ethernet::PROTO;
	} else if (link_proto == DLT_LINUX_SLL) {
		/* First bytes are an SLL Layer */
		first_layer = SLL::PROTO;
	}
	else if (link_proto == DLT_RAW) {
		/* No link layer, suppose we are dealing with IPv4. Hope to be a good guess :-p */
		first_layer = IP::PROTO;
	}
	else {
		/* Create Raw layer */
		RawLayer rawdata(data,length);
		PushLayer(rawdata);
		/* That's all, we can't go further */
		return;
	}

	Decode(data,length,first_layer);
}

/* Just a wrapper for backward compatibility */
void Packet::PacketFromEthernet(const byte* data, size_t length) {
	Decode(data,length,Ethernet::PROTO);
}

void Packet::PacketFromEthernet(const RawLayer& data) {
	/* Construct the packet from the buffer */
	PacketFromEthernet(data.GetPayload().GetRawPointer(), data.GetSize());
}

/* [+] ----------- From IP layer */

/* Construct packet a raw layer */
void Packet::PacketFromIP(const RawLayer& data) {
	/* Construct the packet from the buffer */
	PacketFromIP(data.GetPayload().GetRawPointer(), data.GetSize());
}

/* Constructor from raw data */
void Packet::PacketFromIP(const byte* data, size_t length) {
	Decode(data,length,IP::PROTO);
}

/* Constructor from raw data */
void Packet::PacketFromIPv6(const byte* data, size_t length) {
	Decode(data,length,IPv6::PROTO);
}
