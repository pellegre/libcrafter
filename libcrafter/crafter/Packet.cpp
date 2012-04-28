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
#include "CrafterUtils.h"
#include "RawSocket.h"

using namespace std;
using namespace Crafter;

pthread_mutex_t Packet::mutex_compile;

void Packet::HexDump() {
	Craft();
	size_t lSize = bytes_size;

	byte *pAddressIn = new byte[lSize];

	for (size_t i = 0 ; i < bytes_size  ; i++)
		pAddressIn[i] = raw_data[i];

	char szBuf[100];
	long lIndent = 1;
	long lOutLen, lIndex, lIndex2, lOutLen2;
	long lRelPos;
	struct { char *pData; unsigned long lSize; } buf;
	unsigned char *pTmp,ucTmp;
	unsigned char *pAddress = (unsigned char *)pAddressIn;

   buf.pData   = (char *)pAddress;
   buf.lSize   = lSize;

   while (buf.lSize > 0)
   {
      pTmp     = (unsigned char *)buf.pData;
      lOutLen  = (int)buf.lSize;
      if (lOutLen > 16)
          lOutLen = 16;

      // create a 64-character formatted output line:
      sprintf(szBuf, "                              "
                     "                      "
                     "    %08lX", (long unsigned int) (pTmp-pAddress));
      lOutLen2 = lOutLen;

      for(lIndex = 1+lIndent, lIndex2 = 53-15+lIndent, lRelPos = 0;
          lOutLen2;
          lOutLen2--, lIndex += 2, lIndex2++
         )
      {
         ucTmp = *pTmp++;

         sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
         if(!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
         szBuf[lIndex2] = ucTmp;

         if (!(++lRelPos & 3))     // extra blank after 4 bytes
         {  lIndex++; szBuf[lIndex+2] = ' '; }
      }

      if (!(lRelPos & 3)) lIndex--;

      szBuf[lIndex  ]   = ' ';
      szBuf[lIndex+1]   = ' ';

      cout << szBuf << endl;

      buf.pData   += lOutLen;
      buf.lSize   -= lOutLen;
   }

   delete [] pAddressIn;
}

/* Print Payload */
void Packet::RawString() {
	Craft();
	/* Print raw data in hexadecimal format */
	for(size_t i = 0 ; i < bytes_size ; i++) {
		std::cout << "\\x";
		std::cout << std::hex << (unsigned int)(raw_data)[i];
	}

	cout << endl;
}

void Packet::Print() const {
	std::vector<Layer*>::const_iterator it_layer;

	for (it_layer = Stack.begin() ; it_layer != Stack.end() ; it_layer++)
		(*it_layer)->Print();
}

void Packet::PushLayer(const Layer& user_layer) {
	/* Create a new layer from the one that was supplied by the user */
	Layer* layer = Protocol::AccessFactory()->GetLayerByName(user_layer.GetName());

	/* Call = operator */
	(*layer) = user_layer;

	Stack.push_back(layer);
	/* Update size of the packet */
	bytes_size += layer->GetSize();

	/* Get number of layers */
	size_t layers = Stack.size();
	if ((layers - 1) > 0) {
		layer->PushBottomLayer(Stack[(layers - 2)]);
		Stack[(layers - 2)]->PushTopLayer(layer);
	} else
		layer->PushBottomLayer(0);

	layer->PushTopLayer(0);
}

void Packet::PopLayer() {
	/* Get number of layers */
	size_t layers = Stack.size();

	if(layers > 0) {
		/* Get the top layer */
		Layer* top_layer = Stack[layers-1];

		/* Set the new top layer */
		if( (layers - 1) > 0) {
			Layer* new_top_layer = Stack[layers-2];
			new_top_layer->PushTopLayer(0);
		}

		/* Delete the pop layer */
		bytes_size -= top_layer->GetSize();
		/* Delete the last layer */
		delete top_layer;
		/* Pop back the pointer */
		Stack.pop_back();
	}

}

/* Copy Constructor */
Packet::Packet(const Packet& copy_packet) {
	/* Init the size in bytes of the packet */
	bytes_size = 0;
	/* Init the pointer */
	raw_data = 0;

	/* Push layer one by one */
	vector<Layer*>::const_iterator it_layer;
	for (it_layer = copy_packet.Stack.begin() ; it_layer != copy_packet.Stack.end() ; ++it_layer)
		PushLayer(*(*it_layer));

}

Packet& Packet::operator=(const Packet& right) {
	/* Delete layer one by one */
	vector<Layer*>::iterator it_layer;
	for (it_layer = Stack.begin() ; it_layer != Stack.end() ; ++it_layer)
		delete (*it_layer);

	Stack.clear();

	if(raw_data) {
		delete [] raw_data;
		raw_data = 0;
	}

	/* Init the size in bytes of the packet */
	bytes_size = 0;

	vector<Layer*>::const_iterator it_const;

	for (it_const = right.Stack.begin() ; it_const != right.Stack.end() ; ++it_const)
		PushLayer(*(*it_const));

	return *this;
}

Packet& Packet::operator=(const Layer& right) {
	/* Delete layer one by one */
	vector<Layer*>::iterator it_layer;
	for (it_layer = Stack.begin() ; it_layer != Stack.end() ; ++it_layer)
		delete (*it_layer);

	Stack.clear();

	if(raw_data) {
		delete [] raw_data;
		raw_data = 0;
	}

	/* Init the size in bytes of the packet */
	bytes_size = 0;

	PushLayer(right);

	return *this;
}

/* Copy Constructor */
Packet::Packet(const Layer& copy_layer) {
	/* Init the size in bytes of the packet */
	bytes_size = 0;
	/* Init the pointer */
	raw_data = 0;

	/* Push layer one by one */
	PushLayer(copy_layer);
}

const Packet Packet::operator/(const Layer& right) const {
	Packet ret_packet;

	vector<Layer*>::const_iterator it_const;

	for (it_const = Stack.begin() ; it_const != Stack.end() ; ++it_const)
		ret_packet.PushLayer(*(*it_const));

	ret_packet.PushLayer(right);

	return ret_packet;
}

const Packet Packet::operator/(const Packet& right) const {
	Packet ret_packet;

	vector<Layer*>::const_iterator it_const;

	for (it_const = Stack.begin() ; it_const != Stack.end() ; ++it_const)
		ret_packet.PushLayer(*(*it_const));

	for (it_const = right.Stack.begin() ; it_const != right.Stack.end() ; ++it_const)
		ret_packet.PushLayer(*(*it_const));

	return ret_packet;
}

Packet& Packet::operator/=(const Layer& right) {
	PushLayer(right);
	return *this;
}

Packet& Packet::operator/=(const Packet& right) {
	vector<Layer*>::const_iterator it_const;

	for (it_const = right.Stack.begin() ; it_const != right.Stack.end() ; ++it_const)
		PushLayer(*(*it_const));

	return *this;
}

void Packet::Craft() {
	/* First remove bytes for the raw data */
	if (raw_data) {
		bytes_size = 0;
		delete [] raw_data;
	}

 	if (Stack.size() > 0) {
		/* Craft layer one by one */
		vector<Layer*>::reverse_iterator it_layer;
		for (it_layer = Stack.rbegin() ; it_layer != Stack.rend() ; ++it_layer)
			(*it_layer)->Craft();

		/* Datagram size, including data */
		bytes_size = Stack[0]->GetRemainingSize();

		/* Now, allocate bytes */
		raw_data = new byte[bytes_size];

		Stack[0]->GetData(raw_data);
	} else
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Packet::Craft()","No data in the packet. Nothing to craft.");

}

size_t Packet::GetData(byte* raw_ptr) const {
 	if (Stack.size() > 0)
 		return Stack[0]->GetData(raw_ptr);
 	else
 		return 0;
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
		/* Redefine fields in case is necesary */
		trp_layer->ReDefineActiveFields();

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
void Packet::PacketFromEthernet(const byte* data, size_t length) {
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

	/* First bytes are an Ethernet Layer */
	Ethernet ether_layer;

	/* Check if the data don't fit into an ethernet header */
	if(ether_layer.GetSize() > length) {
		/* Create Raw layer */
		RawLayer rawdata(data,length);
		PushLayer(rawdata);
		/* That's all */
		return;
	}

	size_t n_ether = ether_layer.PutData(data);

	ether_layer.ReDefineActiveFields();

	/* Get size of the remaining data */
	length -= n_ether;

	/* Construct a network layer */
	if (ether_layer.GetType() == 0x0800) {
		/* The first bytes are an IP layer */
		IP ip_layer;

		/* Check if the data don't fit into an ethernet header */
		if(ip_layer.GetSize() > length) {
			/* Create Raw layer */
			RawLayer rawdata(data + n_ether, length);
			PushLayer(ether_layer);
			PushLayer(rawdata);
			/* That's all */
			return;
		}

		/* Put Data */
		size_t n_ip = ip_layer.PutData(data + n_ether);


		/* Get size of the remaining data */
		length -= n_ip;

		/* Verify if the are options on the IP header */
		size_t IP_word_size = ip_layer.GetHeaderLength();
		size_t IP_opt_size = 0;

		if(IP_word_size > 5) IP_opt_size = 4 * (IP_word_size - 5);

		if (IP_opt_size < length && IP_opt_size > 0) {
			/* The options are set as a payload */
			ip_layer.SetPayload(data + n_ip + n_ether, IP_opt_size);
			length -= IP_opt_size;
			n_ip += IP_opt_size;
		} else if (IP_opt_size >= length && IP_opt_size > 0) {
			ip_layer.SetPayload(data + n_ip + n_ether, length);
			PushLayer(ether_layer);
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
				RawLayer rawdata(data + n_ether + n_ip, length);
				PushLayer(ether_layer);
				PushLayer(ip_layer);
				PushLayer(rawdata);
				delete trp_layer;
				/* That's all */
				return;
			}

			n_trp = trp_layer->PutData(data + n_ip + n_ether);
			/* Redefine fields in case is necesary */
			trp_layer->ReDefineActiveFields();

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
					tcp_layer->SetPayload(data + n_ip + n_ether + n_trp, TCP_opt_size);
					length -= TCP_opt_size;
					n_trp += TCP_opt_size;
				} else if (TCP_opt_size >= length && TCP_opt_size > 0) {
					tcp_layer->SetPayload(data + n_ip + n_ether + n_trp, length);
					PushLayer(ether_layer);
					PushLayer(ip_layer);
					PushLayer(*trp_layer);
					delete trp_layer;
					/* That's all */
					return;
				}
			}
		}

		size_t data_length = length;

		/* Create a raw payload with the rest of the data */
		RawLayer raw_layer;

		if(data_length) {

			raw_layer.SetPayload(data + n_ip + n_trp + n_ether, length);
		}

		/* Push each layer into the stack */
		PushLayer(ether_layer);
		PushLayer(ip_layer);
		if(trp_layer) PushLayer(*trp_layer);
		if(data_length) PushLayer(raw_layer);

		/* Delete the temporary layer created */
		if(trp_layer) delete trp_layer;

	} else {

		/* Create Network Layer */
		Layer* net_layer = Protocol::AccessFactory()->GetLayerByID(ether_layer.GetType());

		/* Construct next layer */
		size_t n_net = 0;

		if (net_layer) {

			/* Check if the data don't fit into an ethernet header */
			if(net_layer->GetSize() > length) {
				/* Create Raw layer */
				RawLayer rawdata(data + n_ether, length);
				PushLayer(ether_layer);
				PushLayer(rawdata);
				/* That's all */
				return;
			}

			n_net = net_layer->PutData(data + n_ether);
			net_layer->ReDefineActiveFields();

		}

		length -= n_net;

		/* Create a raw payload with the rest of the data */
		RawLayer raw_layer;

		if(length) {

			raw_layer.SetPayload(data + n_net + n_ether, length);
		}

		/* Push each layer into the stack */
		PushLayer(ether_layer);
		if(net_layer) PushLayer(*net_layer);
		if(length) PushLayer(raw_layer);

		/* Delete the temporary layer created */
		if(net_layer) delete net_layer;

	}
}

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

/* Send a packet */
void Packet::Send(const string& iface) {

	/* Libnet context */
	libnet_t *l;                        /* Libnet context */
	char errbuf[LIBNET_ERRBUF_SIZE];    /* Error messages */

	/* Name of the device */
	char* device;

	/* Find device for sniffing if needed */
	if (iface == "") {
	  /* If user hasn't specified a device */
	  device = pcap_lookupdev (errbuf); /* let pcap find a compatible device */
	  cout << "[@] MESSAGE: Packet::Send() -> Using interface: " << device << endl;
	  if (device == NULL) {
		  /* there was an error */
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "Packet::Send()",
		                 "Opening device -> " + string(errbuf));
		  exit (1);
	  }
	} else
	  device = (char *)iface.c_str();

	/* We should find out if the Ethernet layer is or not */
 	if (Stack.size() > 0) {
 		string name = Stack[0]->GetName();
 		if ( name == "Ethernet") {

 			/* Init libnet context */
 			l = libnet_init (LIBNET_LINK, device, errbuf);

 			/* In case of error */
 			if (l == 0) {
 				PrintMessage(Crafter::PrintCodes::PrintError,
 						     "Packet::Send()",
 			                 "Opening libnet context -> " + string(errbuf));
 			  exit (1);
 			}

 		} else
 			if (name == "IP") {

 			/* Init libnet context */
 			l = libnet_init (LIBNET_RAW4, device, errbuf);

 			/* In case of error */
 			if (l == 0) {
 				PrintMessage(Crafter::PrintCodes::PrintError,
 						     "Packet::Send()",
 			                 "Opening libnet context -> " + string(errbuf));
 			  exit (1);
 			}

 		} else {
			PrintMessage(Crafter::PrintCodes::PrintWarning,
						 "Packet::Send()",
 				         "The first layer in the stack (" + name + ") is not IP or Ethernet.");

 			/* Craft the packet */
 			Craft();

 			/* Create the raw socket */
 			int raw = CreateRawSocket(ETH_P_ALL);

 			/* Bind raw socket to interface */
 			BindRawSocketToInterface(iface.c_str(), raw, ETH_P_ALL);

			/* Write the packet on the wire */
 			if(!SendRawPacket(raw, raw_data, bytes_size)) {
 				PrintMessage(Crafter::PrintCodes::PrintPerror,
 						     "Packet::Send()",
 				             "Sending packet");
 			}

 			return;
 		}

 	} else {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Packet::Send()",
                     "Not data in the packet. ");

 		return;
 	}

 	Ethernet* ether_layer = GetEthernet(*this);

 	if(ether_layer) {

 		/* Set the source MAC address */
 		if (!ether_layer->IsFieldSet("SrcMAC1") && (ether_layer->GetSourceMAC() == Ethernet::DefaultMAC) ) {
 			string LocalMAC = GetMyMAC(iface);
 			ether_layer->SetSourceMAC(LocalMAC);
 		}

 	}

 	ARP* arp_layer = GetARP(*this);

 	if(arp_layer) {

 		/* Set the sender MAC address */
 		if (!arp_layer->IsFieldSet("SndMAC1") && (arp_layer->GetSenderMAC() == ARP::DefaultMAC) ) {
 			if (ether_layer) {
				string LocalMAC = ether_layer->GetSourceMAC();
				arp_layer->SetSenderMAC(LocalMAC);
 			}
 		}

 		/* Set the sender IP address */
 		if (!arp_layer->IsFieldSet("SenderIP") && (arp_layer->GetSenderIP() == ARP::DefaultIP)) {
 			if (ether_layer) {
 				string LocalIP = GetMyIP(iface);
 				arp_layer->SetSenderIP(LocalIP);
 			}
 		}

 	}

 	/* If the default Source IP Address is set, we should change it with the one corresponding to the iface */
 	IP* ip_layer = GetIP(*this);

 	if (ip_layer) {

 		/* Set the IP */
 		if (!ip_layer->IsFieldSet("SourceIP") && (ip_layer->GetSourceIP() == IP::DefaultIP)) {
			string LocalIP = GetMyIP(iface);
			ip_layer->SetSourceIP(LocalIP);
 		}

 	}

	/* Before doing anything weird, craft the packet */
	Craft();

 	/* Put the headers into de libnet context from the top to the bottom */
	vector<Layer*>::reverse_iterator layer_from_top;

	for (layer_from_top = Stack.rbegin() ; layer_from_top != Stack.rend() ; layer_from_top++)
		(*layer_from_top)->LibnetBuild(l);

	if ((libnet_write (l)) == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::Send()",
	                 "Unable to send packet -> " + string(libnet_geterror (l)));
	  exit (1);
	}

	/* Exit cleanly */
	libnet_destroy (l);

}

/* Send a packet */
Packet* Packet::SendRecv(const string& iface, int timeout, int retry, const string& user_filter) {

	/* Libnet context */
	libnet_t *l = 0;                           /* Libnet context */
	char libnet_errbuf[LIBNET_ERRBUF_SIZE];    /* Error messages */
	char libcap_errbuf[PCAP_ERRBUF_SIZE];      /* Error messages */

	/* Name of the device */
	char* device;
	/* Handle for the opened pcap session */
	pcap_t *handle;
	/* IP address of interface */
	bpf_u_int32 netp;
	/* Subnet mask of interface */
	bpf_u_int32 maskp;
	/* Compiled BPF filter */
	struct bpf_program fp;

	byte use_raw_socket = 0;

	/* Find device for sniffing if needed */
	if (iface == "") {
	  /* If user hasn't specified a device */
	  device = pcap_lookupdev (libcap_errbuf); /* let pcap find a compatible device */
	  cout << "[@] MESSAGE: Packet::Send() -> Using interface: " << device << endl;
	  if (device == NULL) {
		  /* there was an error */
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "Packet::SendRecv()",
		                 "Opening device -> " + string(libcap_errbuf));
		  exit (1);
	  }
	} else
	  device = (char *)iface.c_str();

	/* We should find out if the Ethernet layer is present */
 	if (Stack.size() > 0) {
 		string name = Stack[0]->GetName();
 		if (name == "Ethernet") {

 			/* Init libnet context */
 			l = libnet_init (LIBNET_LINK, device, libnet_errbuf);

 			/* In case of error */
 			if (l == 0) {
 				PrintMessage(Crafter::PrintCodes::PrintError,
 						     "Packet::SendRecv()",
 			                 "Opening libnet context: " + string(libnet_errbuf));
 			  exit (1);
 			}

 		} else if (name == "IP") {

 			/* Init libnet context */
 			l = libnet_init (LIBNET_RAW4, device, libnet_errbuf);

 			/* In case of error */
 			if (l == 0) {
 				PrintMessage(Crafter::PrintCodes::PrintError,
 						     "Packet::SendRecv()",
 			                 "Opening libnet context: " + string(libnet_errbuf));
 			  exit (1);
 			}

 		} else {
 			if (user_filter == " ") {
 				PrintMessage(Crafter::PrintCodes::PrintWarning,
 						     "Packet::SendRecv()",
 					         "The first layer in the stack (" + name + ") is not IP or Ethernet and you didn't supply a filter expression. Don't expect any answer.");
 			}else {
 				PrintMessage(Crafter::PrintCodes::PrintWarning,
 						     "Packet::SendRecv()",
 					         "The first layer in the stack (" + name + ") is not IP or Ethernet.");
 			}
 			use_raw_socket = 1;

 			if (user_filter == " ") {
				/* Craft the packet */
				Craft();

				/* Create the raw socket */
				int raw = CreateRawSocket(ETH_P_ALL);

				/* Bind raw socket to interface */
				BindRawSocketToInterface(iface.c_str(), raw, ETH_P_ALL);

				/* Write the packet on the wire */
				if(!SendRawPacket(raw, raw_data, bytes_size)) {
					PrintMessage(Crafter::PrintCodes::PrintPerror,
							     "Packet::SendRecv()",
					             "Sending packet");
				}

				close(raw);

				return 0;
 			}
 		}

 	} else {
			PrintMessage(Crafter::PrintCodes::PrintWarning,
					     "Packet::SendRecv()",
			             "Not data in the packet. ");
 		return 0;
 	}

 	Ethernet* ether_layer = GetEthernet(*this);

 	if(ether_layer) {

 		/* Set the source MAC address */
 		if (!ether_layer->IsFieldSet("SrcMAC1") && (ether_layer->GetSourceMAC() == Ethernet::DefaultMAC) ) {
 			string LocalMAC = GetMyMAC(iface);
 			ether_layer->SetSourceMAC(LocalMAC);
 		}

 	}

 	ARP* arp_layer = GetARP(*this);

 	if(arp_layer) {

 		/* Set the sender MAC address */
 		if (!arp_layer->IsFieldSet("SndMAC1") && (arp_layer->GetSenderMAC() == ARP::DefaultMAC) ) {
 			if (ether_layer) {
				string LocalMAC = ether_layer->GetSourceMAC();
				arp_layer->SetSenderMAC(LocalMAC);
 			}
 		}

 		/* Set the sender IP address */
 		if (!arp_layer->IsFieldSet("SenderIP") && (arp_layer->GetSenderIP() == ARP::DefaultIP)) {
 			if (ether_layer) {
 				string LocalIP = GetMyIP(iface);
 				arp_layer->SetSenderIP(LocalIP);
 			}
 		}

 	}

 	/* If the default Source IP Address is set, we should change it with the one corresponding to the iface */
 	IP* ip_layer = GetIP(*this);

 	if (ip_layer) {

 		/* Set the IP */
 		if (!ip_layer->IsFieldSet("SourceIP") && (ip_layer->GetSourceIP() == IP::DefaultIP)) {
			string LocalIP = GetMyIP(iface);
			ip_layer->SetSourceIP(LocalIP);
 		}

 	}

	/* Before doing anything weird, craft the packet */
	Craft();

	if (!use_raw_socket) {
		/* Put the headers into de libnet context from the top to the bottom */
		vector<Layer*>::reverse_iterator layer_from_top;

		for (layer_from_top = Stack.rbegin() ; layer_from_top != Stack.rend() ; layer_from_top++)
			(*layer_from_top)->LibnetBuild(l);
	}

	/* Set errbuf to 0 length string to check for warnings */
	libcap_errbuf[0] = 0;

	/* Open device for sniffing */
	handle = pcap_open_live (device,  /* device to sniff on */
						     BUFSIZ,  /* maximum number of bytes to capture per packet */
									  /* BUFSIZE is defined in pcap.h */
						     1,       /* promisc - 1 to set card in promiscuous mode, 0 to not */
				  timeout*1000,       /* to_ms - amount of time to perform packet capture in milliseconds */
									  /* 0 = sniff until error */
				      libcap_errbuf); /* error message buffer if something goes wrong */


	if (handle == NULL) {
	  /* There was an error */
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::SendRecv()",
	                 "Listening device -> " + string(libcap_errbuf));
	  exit (1);
	}
	if (strlen (libcap_errbuf) > 0) {
			PrintMessage(Crafter::PrintCodes::PrintWarning,
					     "Packet::SendRecv()",
			              string(libcap_errbuf));

	  libcap_errbuf[0] = 0;    /* re-set error buffer */
	}

	/* Find out the datalink type of the connection */
	if (pcap_datalink (handle) != DLT_EN10MB) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::SendRecv()",
	                 "This sniffer only supports Ethernet cards!");
	  exit (1);
	}

	/* Get the IP subnet mask of the device, so we set a filter on it */
	if (pcap_lookupnet (device, &netp, &maskp, libcap_errbuf) == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::SendRecv()",
                     "Error getting device information " + string(libcap_errbuf));
	  exit (1);
	}

	string filter = "";

	if (user_filter == " ") {
		string check_icmp;

		if (ip_layer) {
			short_word ident = ip_layer->GetIdentification();
			char* str_ident = new char[6];
			sprintf(str_ident,"%d",ident);
			str_ident[5] = 0;
			check_icmp = "( ( (icmp[icmptype] == icmp-unreach) or (icmp[icmptype] == icmp-timxceed) or "
						 "    (icmp[icmptype] == icmp-paramprob) or (icmp[icmptype] == icmp-sourcequench) or "
						 "    (icmp[icmptype] == icmp-redirect) ) and (icmp[12:2] == " + string(str_ident)  + " ) ) ";
			delete [] str_ident;

		} else
			check_icmp = " ";

		vector<string> layer_filter;

		/* Construct the filter for matching packets */
		vector<Layer*>::iterator it_layer;

		for (it_layer = Stack.begin() ; it_layer != Stack.end(); it_layer++) {
			layer_filter.push_back((*it_layer)->MatchFilter());
		}

		filter = "(" + layer_filter[0];

		vector<string>::iterator it_f;

		for(it_f = layer_filter.begin() + 1 ; it_f != layer_filter.end() ; it_f++) {
			vector<string>::iterator last = it_f - 1;
			if ( (*it_f) != " " && (*last) != " " )
				filter += " and " + (*it_f);
			else if ( (*it_f) != " " && (*last) == " ")
				filter += (*it_f);
		}

		if (check_icmp != " ")
			filter += ") or " + check_icmp;
		else
			filter += ")";
	} else
		filter = user_filter;

	//cout << filter << endl;

	/* ----------- Begin Critical area ---------------- */

    pthread_mutex_lock (&mutex_compile);

	/* Compile the filter, so we can capture only stuff we are interested in */
	if (pcap_compile (handle, &fp, filter.c_str(), 0, maskp) == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::SendRecv()",
	                 "Error compiling the filter -> " + string(pcap_geterr(handle)));
		cerr << "[!] Bad filter expression -> " << filter << endl;
	  exit (1);
	}

	/* Set the filter for the device we have opened */
	if (pcap_setfilter (handle, &fp) == -1)	{
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::SendRecv()",
                     "Setting filter -> " + string(pcap_geterr (handle)));
	  exit (1);
	}

	/* We'll be nice and free the memory used for the compiled filter */
	pcap_freecode(&fp);

    pthread_mutex_unlock (&mutex_compile);

	/* ------------ End Critical area ----------------- */

	int r = 0;

	Packet* match_packet = new Packet;

	int count = 0;
	int success = 0;

	while (count < retry) {

		if (!use_raw_socket) {
			if ((libnet_write (l)) == -1) {
				PrintMessage(Crafter::PrintCodes::PrintError,
						     "Packet::SendRecv()",
			                 "Unable to send packet -> " + string(libnet_geterror (l)));
			  exit (1);
			}
		} else {
			/* Create the raw socket */
			int raw = CreateRawSocket(ETH_P_ALL);

			/* Bind raw socket to interface */
			BindRawSocketToInterface(iface.c_str(), raw, ETH_P_ALL);

			/* Write the packet on the wire */
			if(!SendRawPacket(raw, raw_data, bytes_size)) {
				PrintMessage(Crafter::PrintCodes::PrintPerror,
						     "Packet::SendRecv()",
				             "Sending packet");
			}
			/* Close Raw Socket */
			close(raw);
		}

		struct pcap_pkthdr *header;
		const u_char *packet;

		if ((r = pcap_next_ex (handle, &header, &packet)) <= 0) {
			if (r == -1) {
			  /* Pcap error */
				PrintMessage(Crafter::PrintCodes::PrintError,
						     "Packet::SendRecv()",
			                 "Error calling pcap_next_ex() " + string(pcap_geterr (handle)));
			  exit (1);
			}
			/* Otherwise return should be -2 */
		}

		if (r >= 1) {
			match_packet->PacketFromEthernet(packet, header->len);
			success = 1;
			break;
		}

		count++;

	}

	/* Exit cleanly */
	if (!use_raw_socket)
		libnet_destroy (l);

	pcap_close (handle);

	if (success)
		return match_packet;
	else {
		delete match_packet;
		return 0;
	}

}

int Packet::RawSocketSend(int sd) {
	/* IP address in string format */
	char ip_address[16];
	/* Get IP Layer */
	IP* IPLayer = 0;

	/* Check for Internet Layer protocol. Should be a IP Layer object */
	if (Stack[0]->GetName() != "IP") {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::RawSocketSend()",
		             "No IP layer on packet. Cannot write on Raw Socket. ");
		exit(1);
	} else {
		/* Is OK to cast it */
		IPLayer = dynamic_cast<IP*>(Stack[0]);
		strncpy(ip_address , (const char *)(IPLayer->GetDestinationIP()).c_str(), 16);
                int one = 1;
                const int* val = &one;
	        if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		    PrintMessage(Crafter::PrintCodes::PrintError,
				 "Packet::RawSocketSend()",
		                 "Setting IPPROTO_IP option to raw socket");
		    exit(1);
	         }
	}

	/* Create structure for destination */
	struct sockaddr_in din;

	/* Check for Transport Layer Protocol. Should be TCP, UDP or ICMP */
	string transport_layer = Stack[1]->GetName();
	if (transport_layer == "UDP") {
		UDP* udp_layer = dynamic_cast<UDP*>(Stack[1]);
		/* Set destinations structure */
	    din.sin_family = AF_INET;
	    din.sin_port = htons(udp_layer->GetDstPort());
	    din.sin_addr.s_addr = inet_addr(ip_address);
	    memset(din.sin_zero, '\0', sizeof (din.sin_zero));
	} else if (transport_layer == "TCP") {
		TCP* tcp_layer = dynamic_cast<TCP*>(Stack[1]);
		/* Set destinations structure */
	    din.sin_family = AF_INET;
	    din.sin_port = htons(tcp_layer->GetDstPort());
	    din.sin_addr.s_addr = inet_addr(ip_address);
	    memset(din.sin_zero, '\0', sizeof (din.sin_zero));
	} else {
		/* Set destinations structure */
	    din.sin_family = AF_INET;
	    din.sin_port = htons(0);
	    din.sin_addr.s_addr = inet_addr(ip_address);
	    memset(din.sin_zero, '\0', sizeof (din.sin_zero));
	}

	/* Craft data before sending anything */
	Craft();

        int ret = 0;
	if( (ret = sendto(sd, raw_data, bytes_size, 0, (struct sockaddr *)&din, sizeof(din))) < 0) {
		PrintMessage(Crafter::PrintCodes::PrintPerror,
				     "Packet::RawSocketSend()",
				     "Writing on Raw Socket");
	}

	return ret;

}

Packet* Packet::RawSocketSendRecv(int sd, const string& iface, int timeout, int retry, const string& user_filter) {
	/* Error messages */
	char libcap_errbuf[PCAP_ERRBUF_SIZE];

	/* Name of the device */
	char* device;
	/* Handle for the opened pcap session */
	pcap_t *handle;
	/* IP address of interface */
	bpf_u_int32 netp;
	/* Subnet mask of interface */
	bpf_u_int32 maskp;
	/* Compiled BPF filter */
	struct bpf_program fp;

	/* IP address in string format */
	char ip_address_dst[16];
	/* Get IP Layer */
	IP* IPLayer = 0;

	/* Check for Internet Layer protocol. Should be a IP Layer object */
	if (Stack[0]->GetName() != "IP") {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::RawSocketSendRecv()",
		             "No IP layer on packet. Cannot write on Raw Socket.");
		exit(1);
	} else {
		/* Is OK to cast it */
		IPLayer = dynamic_cast<IP*>(Stack[0]);
		strncpy(ip_address_dst, (const char *)(IPLayer->GetDestinationIP()).c_str(), 16);
	}

	/* Find device for sniffing if needed */
	if (iface == "") {
	  /* If user hasn't specified a device */
	  device = pcap_lookupdev (libcap_errbuf); /* let pcap find a compatible device */
	  cout << "[@] MESSAGE: Packet::Send() -> Using interface: " << device << endl;
	  if (device == NULL) {
		  /* there was an error */
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "Packet::RawSocketSendRecv()",
		                 "Opening device -> " + string(libcap_errbuf));
		  exit (1);
	  }
	} else
	  device = (char *)iface.c_str();

	/* Create structure for destination */
	struct sockaddr_in din;

	/* Check for Transport Layer Protocol. Should be TCP, UDP or ICMP */
	string transport_layer = Stack[1]->GetName();
	if ( transport_layer == "UDP") {
		UDP* udp_layer = dynamic_cast<UDP*>(Stack[1]);
		/* Set destinations structure */
	    din.sin_family = AF_INET;
	    din.sin_port = htons(udp_layer->GetDstPort());
	    din.sin_addr.s_addr = inet_addr(ip_address_dst);
	    memset(din.sin_zero, '\0', sizeof (din.sin_zero));
	} else if (transport_layer == "TCP") {
		TCP* tcp_layer = dynamic_cast<TCP*>(Stack[1]);
		/* Set destinations structure */
	    din.sin_family = AF_INET;
	    din.sin_port = htons(tcp_layer->GetDstPort());
	    din.sin_addr.s_addr = inet_addr(ip_address_dst);
	    memset(din.sin_zero, '\0', sizeof (din.sin_zero));
	} else {
		/* Set destinations structure */
	    din.sin_family = AF_INET;
	    din.sin_port = htons(0);
	    din.sin_addr.s_addr = inet_addr(ip_address_dst);
	    memset(din.sin_zero, '\0', sizeof (din.sin_zero));
	}

 	/* If the default Source IP Address is set, we should change it with the one corresponding to the iface */
 	IP* ip_layer = GetIP(*this);

 	if (ip_layer) {

 		/* Set the IP */
 		if (!ip_layer->IsFieldSet("SourceIP") && (ip_layer->GetSourceIP() == IP::DefaultIP) ) {
			string LocalIP = GetMyIP(string(device));
			ip_layer->SetSourceIP(LocalIP);
 		}

 	}


	/* Craft data before sending anything */
	Craft();

	int one = 1;
	const int *val = &one;

	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::RawSocketSendRecv()",
		             "Setting IPPROTO_IP option to raw socket");
		exit(1);
	}

	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, device, iface.size())) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::RawSocketSendRecv()",
		             "Setting SOL_SOCKET option to raw socket");
		exit(1);
	}

	/* Set errbuf to 0 length string to check for warnings */
	libcap_errbuf[0] = 0;

	/* Open device for sniffing */
	handle = pcap_open_live (device,  /* device to sniff on */
						     BUFSIZ,  /* maximum number of bytes to capture per packet */
									  /* BUFSIZE is defined in pcap.h */
						     1,       /* promisc - 1 to set card in promiscuous mode, 0 to not */
				  timeout*1000,       /* to_ms - amount of time to perform packet capture in milliseconds */
									  /* 0 = sniff until error */
				      libcap_errbuf); /* error message buffer if something goes wrong */


	if (handle == NULL) {
	  /* There was an error */
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::RawSocketSendRecv()",
	                 "Listening device -> " + string(libcap_errbuf));
	  exit (1);
	}
	if (strlen (libcap_errbuf) > 0) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Packet::RawSocketSendRecv()",
			         string(libcap_errbuf));

	  libcap_errbuf[0] = 0;    /* re-set error buffer */
	}

	/* Find out the datalink type of the connection */
	if (pcap_datalink (handle) != DLT_EN10MB) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::RawSocketSendRecv()",
	                 "This sniffer only supports Ethernet cards!");
	  exit (1);
	}

	/* Get the IP subnet mask of the device, so we set a filter on it */
	if (pcap_lookupnet (device, &netp, &maskp, libcap_errbuf) == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::RawSocketSendRecv()",
                     "[!] Error getting information of the device -> " + string(libcap_errbuf));
	  exit (1);
	}

	string filter = "";

	if (user_filter == " ") {
		string check_icmp;

		if (ip_layer) {
			short_word ident = ip_layer->GetIdentification();
			char* str_ident = new char[6];
			sprintf(str_ident,"%d",ident);
			str_ident[5] = 0;
			check_icmp = "( ( (icmp[icmptype] == icmp-unreach) or (icmp[icmptype] == icmp-timxceed) or "
						 "    (icmp[icmptype] == icmp-paramprob) or (icmp[icmptype] == icmp-sourcequench) or "
						 "    (icmp[icmptype] == icmp-redirect) ) and (icmp[12:2] == " + string(str_ident)  + " ) ) ";

		} else
			check_icmp = " ";

		vector<string> layer_filter;

		/* Construct the filter for matching packets */
		vector<Layer*>::iterator it_layer;

		for (it_layer = Stack.begin() ; it_layer != Stack.end(); it_layer++) {
			layer_filter.push_back((*it_layer)->MatchFilter());
		}

		filter = "(" + layer_filter[0];

		vector<string>::iterator it_f;

		for(it_f = layer_filter.begin() + 1 ; it_f != layer_filter.end() ; it_f++) {
			vector<string>::iterator last = it_f - 1;
			if ( (*it_f) != " " && (*last) != " " )
				filter += " and " + (*it_f);
			else if ( (*it_f) != " " && (*last) == " ")
				filter += (*it_f);
		}

		if (check_icmp != " ")
			filter += ") or " + check_icmp;
		else
			filter += ")";
	} else
		filter = user_filter;

	/* ----------- Begin Critical area ---------------- */

    pthread_mutex_lock (&mutex_compile);

	/* Compile the filter, so we can capture only stuff we are interested in */
	if (pcap_compile (handle, &fp, filter.c_str(), 0, maskp) == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::RawSocketSendRecv()",
	                 "Error compiling the filter -> " + string(pcap_geterr(handle) ));
		cerr << "[!] Bad filter expression -> " << filter << endl;
	  exit (1);
	}

	/* Set the filter for the device we have opened */
	if (pcap_setfilter (handle, &fp) == -1)	{
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Packet::RawSocketSendRecv()",
		             "[!] Setting filter -> " + string(pcap_geterr (handle)));
	  exit (1);
	}

    pthread_mutex_unlock (&mutex_compile);

	/* ------------ End Critical area ----------------- */

    int count = 0;
    int success = 0;

	Packet* match_packet = new Packet;

    while (count < retry) {

		if(sendto(sd, raw_data, bytes_size, 0, (struct sockaddr *)&din, sizeof(din)) < 0) {
			PrintMessage(Crafter::PrintCodes::PrintPerror,
					     "Packet::RawSocketSendRecv()",
			             "Writing on raw socket -> ");
			exit(1);
		}

		struct pcap_pkthdr *header;
		const u_char *packet;
		int r;

		if ((r = pcap_next_ex (handle, &header, &packet)) <= 0) {
			if (r == -1) {
			  /* Pcap error */
				PrintMessage(Crafter::PrintCodes::PrintError,
						     "Packet::RawSocketSendRecv()",
			                 "Error calling pcap_next_ex " + string(pcap_geterr(handle)));
			  exit (1);
			}
			/* Otherwise return should be -2 */
		}

		if (r >= 1) {
			match_packet->PacketFromEthernet(packet, header->len);
			success = 1;
			break;
		}

		count++;
	}

	pcap_close (handle);

	if (success)
		return match_packet;
	else
		return 0;

}

void Packet::InitMutex() {
    pthread_mutex_init(&Packet::mutex_compile, NULL);
}

void Packet::DestroyMutex() {
    pthread_mutex_destroy(&Packet::mutex_compile);
}

/* Destructor */
Packet::~Packet() {
	/* Delete layer one by one */
	vector<Layer*>::iterator it_layer;
	for (it_layer = Stack.begin() ; it_layer != Stack.end() ; ++it_layer)
		delete (*it_layer);

	Stack.clear();

	if(raw_data) {
		delete [] raw_data;
		raw_data = 0;
	}
}
