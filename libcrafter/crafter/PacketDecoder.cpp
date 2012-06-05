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
#include <pcap.h>

using namespace std;
using namespace Crafter;

/* [+] ----------- From Link layer */

/* Constructor from raw data */
void Packet::PacketFromLinkLayer(const byte* data, size_t length, int link_proto) {
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

	/* Next layer type (should be somewhere on the link protocol header) */
	word next_layer = 0;
	/* Length of the link layer */
	size_t n_link = 0;

	/* Link layer type */
	Layer* link_layer = 0;

	if(link_proto == DLT_EN10MB) {
		/* First bytes are an Ethernet Layer */
		link_layer = new Ethernet;
		next_layer = dynamic_cast<Ethernet*>(link_layer)->GetType();

	} else if (link_proto == DLT_LINUX_SLL) {
		/* First bytes are an SLL Layer */
		link_layer = new SLL;
		next_layer = dynamic_cast<SLL*>(link_layer)->GetProtocol();
	}
	else {
		/* Create Raw layer */
		RawLayer rawdata(data,length);
		PushLayer(rawdata);
		/* That's all, we can't go further */
		return;
	}

	/* Check if the data don't fit into an ethernet header */
	if(link_layer->GetSize() > length) {
		/* Create Raw layer */
		RawLayer rawdata(data,length);
		PushLayer(rawdata);
		/* That's all */
		return;
	}

	n_link = link_layer->PutData(data);

	/* Get size of the remaining data */
	length -= n_link;

	/* Push this layer */
	PushLayer(*link_layer);

	/* Delete the link layer */
	delete link_layer;

	/* Construct a network layer */
	if (next_layer == 0x0800) {

		/* Get data from IPv4 */
		GetFromIP(data + n_link,length);

	} else {

		/* Create Network Layer */
		Layer* net_layer = Protocol::AccessFactory()->GetLayerByID(next_layer);

		/* Construct next layer */
		size_t n_net = 0;

		if (net_layer) {

			/* Check if the data don't fit into an ethernet header */
			if(net_layer->GetSize() > length) {
				/* Create Raw layer */
				RawLayer rawdata(data + n_link, length);
				PushLayer(rawdata);
				/* That's all */
				return;
			}

			n_net = net_layer->PutData(data + n_link);

		}

		length -= n_net;

		/* Create a raw payload with the rest of the data */
		RawLayer raw_layer;

		if(length) {

			raw_layer.SetPayload(data + n_net + n_link, length);
		}

		if(net_layer) PushLayer(*net_layer);
		if(length) PushLayer(raw_layer);

		/* Delete the temporary layer created */
		if(net_layer) delete net_layer;

	}
}

/* Just a wrapper for backward compatibility */
void Packet::PacketFromEthernet(const byte* data, size_t length) {
	PacketFromLinkLayer(data,length,DLT_EN10MB);
}

void Packet::PacketFromEthernet(const RawLayer& data) {
	/* Get size of the layer */
	size_t layer_size = data.GetSize();

	/* Allocate memory and put the data into a buffer */
	byte* buffer = new byte[layer_size];
	data.GetRawData(buffer);

	/* Construct the packet from the buffer */
	PacketFromEthernet(buffer, data.GetSize());

	/* Delete buffer */
	delete [] buffer;
}

/* [+] ----------- From IP layer */

/* Construct packet a raw layer */
void Packet::PacketFromIP(const RawLayer& data) {
	/* Get size of the layer */
	size_t layer_size = data.GetSize();

	/* Allocate memory and put the data into a buffer */
	byte* buffer = new byte[layer_size];
	data.GetRawData(buffer);

	/* Construct the packet from the buffer */
	PacketFromIP(buffer, data.GetSize());

	/* Delete buffer */
	delete [] buffer;
}

void Packet::GetFromIP(const byte* data, size_t length) {
	/* The first bytes are an IP layer */
	IP ip_layer;

	/* Check if the data don't fit into an ethernet header */
	if(ip_layer.GetSize() > length) {
		/* Create Raw layer */
		RawLayer rawdata(data, length);
		PushLayer(rawdata);
		/* That's all */
		return;
	}

	/* Put Data */
	size_t n_ip = ip_layer.PutData(data);


	/* Get size of the remaining data */
	length -= n_ip;

	/* Verify if the are options on the IP header */
	size_t IP_word_size = ip_layer.GetHeaderLength();
	size_t IP_opt_size = 0;

	if(IP_word_size > 5) IP_opt_size = 4 * (IP_word_size - 5);

	if (IP_opt_size < length && IP_opt_size > 0) {
		/* The options are set as a payload */
		ip_layer.SetPayload(data + n_ip, IP_opt_size);
		length -= IP_opt_size;
		n_ip += IP_opt_size;
	} else if (IP_opt_size >= length && IP_opt_size > 0) {
		ip_layer.SetPayload(data + n_ip, length);
		PushLayer(ip_layer);
		/* That's all */
		return;
	}

	/* Then, create the next protocol */
	Layer* trp_layer = Protocol::AccessFactory()->GetLayerByID(ip_layer.GetProtocol());

	/* Construct transport layer */
	size_t n_trp = 0;

	if (trp_layer) {

		if(trp_layer->GetSize() > length) {
			/* Create Raw layer */
			RawLayer rawdata(data + n_ip, length);
			PushLayer(ip_layer);
			PushLayer(rawdata);
			delete trp_layer;
			/* That's all */
			return;
		}

		n_trp = trp_layer->PutData(data + n_ip);

		/* Get size of the remaining data */
		length -= n_trp;

		/* If we are dealing with a TCP layer, we should check for options */
		if (trp_layer->GetName() == "TCP") {
			/* Cast the layer */
			TCP *tcp_layer = dynamic_cast<TCP *>(trp_layer);
			size_t TCP_word_size = tcp_layer->GetDataOffset();

			size_t TCP_opt_size = 0;

			if(TCP_word_size > 5) TCP_opt_size = 4 * (TCP_word_size - 5);

			if (TCP_opt_size < length && TCP_opt_size > 0) {
				/* The options are set as a payload */
				tcp_layer->SetPayload(data + n_ip + n_trp, TCP_opt_size);
				length -= TCP_opt_size;
				n_trp += TCP_opt_size;
			} else if (TCP_opt_size >= length && TCP_opt_size > 0) {
				tcp_layer->SetPayload(data + n_ip + n_trp, length);
				PushLayer(ip_layer);
				PushLayer(*trp_layer);
				delete trp_layer;
				/* That's all */
				return;
			}
		} else if (trp_layer->GetName() == "ICMP") {
                    /* If we are dealing with an ICMP layer, we should check for extensions */
                    ICMP *icmp_layer = dynamic_cast<ICMP *>(trp_layer);
                    word icmp_type = icmp_layer->GetType();
                    word icmp_length = 4 * icmp_layer->GetLength();
                    /* Non-Compliant applications don't set the Length field. According to RFC4884,
                     * Compliant applications should assume no extensions in this case. However, it
                     * is advised to consider a 128-octet original datagram to keep compatibility. */
                    if (icmp_length == 0 && length > 128)
                        icmp_length = 128;
                    /* According to RFC4884, specific types with a length field set have extensions */
                    if ((icmp_type == ICMP::DestinationUnreachable ||
                         icmp_type == ICMP::TimeExceeded ||
                         icmp_type == ICMP::ParameterProblem) &&
                        icmp_length > 0) {
                        PushLayer(ip_layer);
                        PushLayer(*trp_layer);
                        if (length >= icmp_length) {
                            RawLayer original_payload(data + n_ip + n_trp, icmp_length);
                            length -= icmp_length;
                            PushLayer(original_payload);
                        } else {
                            RawLayer rawdata(data + n_ip + n_trp, length);
                            PushLayer(rawdata);
                            delete trp_layer;
                            return;
                        }
                        if (length > 0) {
                            ICMPExtension icmp_extension;
                            size_t n_ext = icmp_extension.PutData(data + n_ip + n_trp + icmp_length);
                            length -= n_ext;
                            PushLayer(icmp_extension);
                            const byte *extension_data = data + n_ip + n_trp + icmp_length + n_ext;
                            while (length > 0) {
                                ICMPExtensionObject icmp_extension_object_header;
                                size_t n_objhdr = icmp_extension_object_header.PutData(extension_data);
                                PushLayer(icmp_extension_object_header);
                                length -= n_objhdr;
                                extension_data += n_objhdr;
                                word icmp_extension_object_length =
                                    icmp_extension_object_header.GetLength() - n_objhdr;
                                std::string icmp_extension_object_name =
                                    icmp_extension_object_header.GetClassName();
                                /* Some ICMP extensions (such as MPLS) have more than one entry */
                                while (length > 0 && icmp_extension_object_length > 0) {
                                    Layer* icmp_extension_layer =
                                        Protocol::AccessFactory()->GetLayerByName(icmp_extension_object_name);
                                    size_t n_pay = icmp_extension_layer->PutData(extension_data);
                                    PushLayer(*icmp_extension_layer);
                                    icmp_extension_object_length -= n_pay;
                                    length -= n_pay;
                                    extension_data += n_pay;
                                }
                            }
                        }
                        delete trp_layer;
			return;
                    }
                }

	}

	size_t data_length = length;

	/* Create a raw payload with the rest of the data */
	RawLayer raw_layer;

	if(data_length) {
		raw_layer.SetPayload(data + n_ip + n_trp, length);
	}

	/* Push each layer into the stack */
	PushLayer(ip_layer);
	if(trp_layer) PushLayer(*trp_layer);
	if(data_length) PushLayer(raw_layer);

	/* Delete the temporary layer created */
	if(trp_layer) delete trp_layer;
}

/* Constructor from raw data */
void Packet::PacketFromIP(const byte* data, size_t length) {

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

	GetFromIP(data,length);
}
