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

#include <sstream>

#include "config.h"

#include "Packet.h"
#include "Crafter.h"
#include "Utils/RawSocket.h"

using namespace std;
using namespace Crafter;

pthread_mutex_t Packet::mutex_compile;

template<typename T>
static T fromString(const std::string& str) {
	std::istringstream s(str);
	T t;
	s >> t;
	return t;
}

void Packet::HexDump(ostream& str) {
	if(!pre_crafted)
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

      str << szBuf << endl;

      buf.pData   += lOutLen;
      buf.lSize   -= lOutLen;
   }

   delete [] pAddressIn;
}

/* Print Payload */
void Packet::RawString(ostream& str) {
	if(!pre_crafted)
		Craft();
	/* Print raw data in hexadecimal format */
	for(size_t i = 0 ; i < bytes_size ; i++) {
		str << "\\x";
		str << std::hex << (unsigned int)(raw_data)[i];
	}

	str << endl;
}

void Packet::Print(ostream& str) const {
	std::vector<Layer*>::const_iterator it_layer;

	for (it_layer = Stack.begin() ; it_layer != Stack.end() ; it_layer++)
		(*it_layer)->Print(str);
}

void Packet::Print() const {
	Print(std::cout);
}

void Packet::PushLayer(Layer* layer)
{
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

void Packet::PushLayer(const Layer& user_layer) {
	/* Create a new layer from the one that was supplied by the user */
	Layer* layer = Protocol::AccessFactory()->GetLayerByName(user_layer.GetName());

	/* Call = operator */
	(*layer) = user_layer;

	PushLayer(layer);
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

timeval Packet::GetTimestamp() const {
	return ts;
}

void Packet::SetTimestamp(timeval timestamp) {
	ts = timestamp;
}

Layer* Packet::operator[](size_t pos) {
	if(pos < Stack.size())
		return Stack[pos];
	else {
		Crafter::PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Packet::operator[]",
		             "Layer requested out of bounds.");
		return 0;
	}
}

const Layer* Packet::operator[](size_t pos) const {
	if(pos < Stack.size())
		return Stack[pos];
	else {
		Crafter::PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Packet::operator[]",
		             "Layer requested out of bounds.");
		return 0;
	}
}

Packet Packet::SubPacket(LayerStack::const_iterator begin, LayerStack::const_iterator end) const {
	Packet pck;
	LayerStack::const_iterator it = begin;
	for(; it != end ; it++)
		pck.PushLayer(*(*it));
	return pck;
}

Packet Packet::SubPacket(size_t begin, size_t end) const {
	Packet pck;
	for(size_t i = begin; i < end ; i++)
		pck.PushLayer(*(Stack[i]));
	return pck;
}

/* Copy Constructor */
Packet::Packet(const Packet& copy_packet) : raw_data(0), bytes_size(0), pre_crafted(0), ts(copy_packet.ts) {
	/* Push layer one by one */
	vector<Layer*>::const_iterator it_layer;
	for (it_layer = copy_packet.Stack.begin() ; it_layer != copy_packet.Stack.end() ; ++it_layer)
		PushLayer(*(*it_layer));

}

Packet::Packet(const byte* data, size_t length, short_word proto_id) : raw_data(0), bytes_size(0), pre_crafted(0) {
	GetFromLayer(data,length,proto_id);
}

Packet::Packet(const RawLayer& data, short_word proto_id) : raw_data(0), bytes_size(0), pre_crafted(0) {
	GetFromLayer(data.GetPayload().GetRawPointer(),data.GetSize(),proto_id);
}

Packet& Packet::operator=(const Packet& right) {
	/* Copy time stamp */
	ts = right.ts;

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

	/* Copy the Pre-Crafted flag */
	pre_crafted = right.pre_crafted;

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
	/* Put the Pre-Crafted flag at zero */
	pre_crafted = 0;

	PushLayer(right);

	return *this;
}

/* Copy Constructor */
Packet::Packet(const Layer& copy_layer) : raw_data(0), bytes_size(0), pre_crafted(0) {
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

void Packet::PreCraft() {
	/* Craft the packet */
	Craft();
	pre_crafted = 1;
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

size_t Packet::GetData(byte* raw_ptr) {
	/* Craft the data */
	if(!pre_crafted)
		Craft();
 	if (Stack.size() > 0)
 		return Stack[0]->GetData(raw_ptr);
 	else
 		return 0;
}

const byte* Packet::GetRawPtr() {
	/* Craft the data */
	if(!pre_crafted)
		Craft();
	/* Return raw pointer */
	return raw_data;
}

const byte* Packet::GetBuffer() const {
	return raw_data;
}

/* Send a packet */
int Packet::Send(const string& iface) {
	/* Check the size of the stack */
	if(Stack.size() == 0) {

		PrintMessage(Crafter::PrintCodes::PrintWarning,
					 "Packet::Send()",
					 "Not data in the packet. ");
		return 0;

	 }

	/* Craft the packet, so we fill all the information needed */
	if(!pre_crafted)
		Craft();

	/* Get the ID of the first layer */
	word current_id = Stack[0]->GetID();

	/* ----------- Begin Critical area ---------------- */

	pthread_mutex_lock (&mutex_compile);

	/* Request a raw socket with this specific protocol */
	int raw = SocketSender::RequestSocket(iface,current_id);

	pthread_mutex_unlock (&mutex_compile);

	/* ------------ End Critical area ----------------- */

	/* Write the packet on the wire */
	return SocketSender::SendSocket(raw, current_id, raw_data, bytes_size);
}

/* Send a packet */
Packet* Packet::SendRecv(const string& iface, double timeout, int retry, const string& user_filter) {
	if(Stack.size() == 0) {

		PrintMessage(Crafter::PrintCodes::PrintWarning,
					 "Packet::SendRecv()",
					 "Not data in the packet. ");
		return 0;

	 }

	word current_id = Stack[0]->GetID();

	/* ----------- Begin Critical area ---------------- */

	pthread_mutex_lock (&mutex_compile);

	/* Link layer object, or some unknown protocol */
	int raw = SocketSender::RequestSocket(iface,current_id);

	pthread_mutex_unlock (&mutex_compile);

	/* ------------ End Critical area ----------------- */
	return SocketSendRecv(raw, iface, timeout, retry, user_filter);
}

int Packet::SocketSend(int sd) {
	if(Stack.size() == 0) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
					 "Packet::SocketSend()",
					 "Not data in the packet. ");
		return 0;
	 }

	/* Craft the packet */
	if(!pre_crafted)
		Craft();

	word current_id = Stack[0]->GetID();

	return SocketSender::SendSocket(sd,current_id,raw_data,bytes_size);
}

Packet* Packet::SocketSendRecv(int raw, const string& iface, double timeout, int retry, const string& user_filter) {
	char libcap_errbuf[PCAP_ERRBUF_SIZE];      /* Error messages */

	/* Name of the device */
	const char* device = iface.c_str();
	/* Handle for the opened pcap session */
	pcap_t *handle;
	/* IP address of interface */
	bpf_u_int32 netp = 0;
	/* Subnet mask of interface */
	bpf_u_int32 maskp = 0;
	/* Compiled BPF filter */
	struct bpf_program fp;

	if(Stack.size() == 0) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
					 "Packet::SocketSendRecv()",
					 "Not data in the packet. ");
		return 0;
	 }

	/* Craft the packet */
	if(!pre_crafted)
		Craft();

	word current_id = Stack[0]->GetID();

	if (current_id != Ethernet::PROTO &&
		current_id != IP::PROTO       &&
		current_id != IPv6::PROTO     && user_filter == " ") {

		/* Print a warning message */
		PrintMessage(Crafter::PrintCodes::PrintWarning,
					 "Packet::SocketSendRecv()",
					 "The first layer in the stack (" + Stack[0]->GetName() + ") is not IP or Ethernet.");

		/* Write the packet on the wire */
		if(SocketSender::SendSocket(raw, current_id, raw_data, bytes_size) < 0) {
			PrintMessage(Crafter::PrintCodes::PrintWarningPerror,
						 "Packet::SocketSendRecv()",
						 "Sending packet (PF_PACKET socket)");
		}
		return 0;
	}

	/* Set error buffer to 0 length string to check for warnings */
	libcap_errbuf[0] = 0;

	/* Open device for sniffing */
	handle = pcap_open_live (device,  /* device to sniff on */
						     BUFSIZ,  /* maximum number of bytes to capture per packet */
									  /* BUFSIZE is defined in stdio.h (recommended buffer value for host) */
				                  1,  /* promisc - 1 to set card in promiscuous mode, 0 to not */
		        				  1,  /* to_ms - amount of time to delay a read */
									  /* 0 = sniff until error */
				      libcap_errbuf); /* error message buffer if something goes wrong */
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
	pcap_set_immediate_mode(handle, 1); /* We want the response ASAP */
#endif
	if (pcap_setnonblock(handle, 1, libcap_errbuf)) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
					     "Packet::SocketSendRecv()",
			              string(libcap_errbuf));

	  libcap_errbuf[0] = 0;    /* re-set error buffer */
	}

	if (handle == NULL)
	  /* There was an error */
		throw std::runtime_error("Packet::SocketSendRecv() : Listening device " + string(libcap_errbuf));

	if (strlen (libcap_errbuf) > 0) {
			PrintMessage(Crafter::PrintCodes::PrintWarning,
					     "Packet::SocketSendRecv()",
			              string(libcap_errbuf));

	  libcap_errbuf[0] = 0;    /* re-set error buffer */
	}

	int link_type = pcap_datalink(handle);

	string filter;
	if (user_filter != " ")
		filter = user_filter;
	else {
		stringstream s;
		GetFilter(s);
		filter = s.str();
	}

	IPLayer *ip_layer = GetLayer<IPLayer>();
	if (ip_layer && ip_layer->GetID() == IP::PROTO)
		/* Get the IP subnet mask of the device, so we set a filter on it */
		if (pcap_lookupnet (device, &netp, &maskp, libcap_errbuf) == -1)
			throw std::runtime_error("Packet::GetFilter() : Error getting device"
					"information " + string(libcap_errbuf));

	/* ----------- Begin Critical area ---------------- */

    pthread_mutex_lock (&mutex_compile);

	/* Compile the filter, so we can capture only stuff we are interested in */
	if (pcap_compile (handle, &fp, filter.c_str(), 0, maskp) == -1) {
		cerr << "[!] Bad filter expression -> " << filter << endl;
		throw std::runtime_error("Packet::SocketSendRecv() : Error compiling the filter : " + string(pcap_geterr(handle)));
	}
	/* Set the filter for the device we have opened */
	if (pcap_setfilter (handle, &fp) == -1)
		throw std::runtime_error("Packet::SocketSendRecv() : Setting filter : " + string(pcap_geterr (handle)));

	/* We'll be nice and free the memory used for the compiled filter */
	pcap_freecode(&fp);

    pthread_mutex_unlock (&mutex_compile);

	/* ------------ End Critical area ----------------- */

	Packet* match_packet = new Packet;
	int count = 0;
	int success = 0;

	fd_set read_handle;
	FD_ZERO(&read_handle);
	int fd = pcap_get_selectable_fd(handle);

	while (count < retry) {
		struct timeval tv = { (int)timeout, (((int)(timeout*1000)) % 1000) * 1000 };

		/* Write the packet on the wire */
		if(SocketSender::SendSocket(raw, current_id, raw_data, bytes_size) < 0) {
			PrintMessage(Crafter::PrintCodes::PrintWarningPerror,
						 "Packet::SocketSendRecv()",
						 "Sending packet ");
			return 0;
		}
		struct pcap_pkthdr header;
		const u_char *packet;


		FD_SET(fd, &read_handle);
select:
		int ret = select(fd + 1, &read_handle, NULL, NULL, &tv);
		if (!ret) /* timeout, try again */ {
			++count;
			continue;
		}
		if (ret < 0) {
			if (errno == EINTR)
				goto select;
			PrintMessage(Crafter::PrintCodes::PrintWarningPerror,
						 "Packet::SocketSendRecv()",
						 "select() failed ");
			return 0;
		}
		if ((packet = pcap_next(handle, &header))) {
			match_packet->PacketFromLinkLayer(packet, header.len, link_type);
			success = 1;
			break;
		}
		/* We arrived here because some packets were received on the interface
		 * but were filtered out by the bpf filter. */
		goto select;
	}
	pcap_close (handle);

	if (success)
		return match_packet;
	else {
		delete match_packet;
		return 0;
	}
}

void Packet::GetFilter(stringstream& filter) const {
	IPLayer *ip_layer = GetLayer<IPLayer>();
	if (!ip_layer)
		return;

	/*
	 * Create a filter matching an expected answer
	 */
	vector<string> layer_filter;
	vector<Layer*>::const_iterator it_layer = Stack.begin(), it_end = Stack.end();
	string str_filter;
	/* Find first non empty filter */
	do {
		str_filter = (*it_layer)->MatchFilter();
		++it_layer;
	} while (str_filter == " " && it_layer != it_end);
	/* We have at least one filter for an expected answer */
	if (str_filter != " ") {
		filter << "(" << str_filter;
		for ( ; it_layer != it_end; ++it_layer) {
			str_filter = (*it_layer)->MatchFilter();
			/* Compose it with sublayers, if applicable */
			if (str_filter != " ") filter << " and " << str_filter;
		}
		filter << ")";
	}

	/*
	 * Handle ICMP replies for that packet
	 */
	size_t transport_offset;
	std::string transport_encapsulation;
	filter << " or ( ";
	if (ip_layer->GetID() == IP::PROTO) {
		IP *ipv4_layer = dynamic_cast<IP*>(ip_layer);

#define MATCH(offset, len, value) \
		"( icmp[" << 8 + offset << ":" << len << "] == " << value << " )"

		filter << "icmp and ( " /* IPv4 ICMP Transport protocol */
						"(icmp[icmptype] == icmp-unreach) or " /* Is an ICMP */
						"(icmp[icmptype] == icmp-timxceed) or " /* carrying */
						"(icmp[icmptype] == icmp-paramprob) or " /* an useful */
						"(icmp[icmptype] == icmp-sourcequench) or " /* payload */
						"(icmp[icmptype] == icmp-redirect) "
						") and ( " /* Match the uuid */
							MATCH(4, 2, ipv4_layer->GetIdentification()) " or " /* Same IP ID */
							" ( " /* Or same addresses */
								MATCH(12, 4, ntohl(*(uint32_t*)ipv4_layer->GetRawSourceIP()))
								" and "
								MATCH(16,4, ntohl(*(uint32_t*)ipv4_layer->GetRawDestinationIP()))
								; /* Payload match is common to v4-v6 */
		transport_offset = ipv4_layer->GetHeaderLength() * 4 + 8;
		transport_encapsulation = "icmp";
#undef MATCH
	} else if(ip_layer->GetID() == IPv6::PROTO) {
		IPv6 *ipv6_layer = dynamic_cast<IPv6*>(ip_layer);
#define MATCH(offset, len, value) \
		"( ip6[" << 48 + offset << ":" << len << "] == " << value << " )"
		uint32_t *sourceip = (uint32_t*)ipv6_layer->GetRawSourceIP();
		uint32_t *destip = (uint32_t*)ipv6_layer->GetRawSourceIP();
		filter << "icmp6 and ( " /* IPv6 ICMP6 TP */
						"(ip6[40] == 1) or" /* With useful payload types */
						"(ip6[40] == 2) or"
						"(ip6[40] == 3) or"
						"(ip6[40] == 4) "
						") and ( " /* Match the uuid  - 20 bits */
							" ip6[48:4] & 0x000fffff == " << ipv6_layer->GetFlowLabel()
							<< " or ( " /* Same addresses */
								MATCH(8, 4, ntohl(sourceip[0])) " and "
								MATCH(12, 4, ntohl(sourceip[1])) " and "
								MATCH(16, 4, ntohl(sourceip[2])) " and "
								MATCH(20, 4, ntohl(sourceip[3])) " and "
								MATCH(24, 4, ntohl(destip[0])) " and "
								MATCH(28, 4, ntohl(destip[1])) " and "
								MATCH(32, 4, ntohl(destip[2])) " and "
								MATCH(36, 4, ntohl(destip[3]))
								;
		transport_offset = 88;
		transport_encapsulation = "ip6";
#undef MATCH
	}

	Layer* next_layer = ip_layer->GetTopLayer();
	if(next_layer && next_layer->GetSize() >= 1) {
#define MATCH(offset, len, value) \
		"( " << transport_encapsulation << "[" << transport_offset + offset \
		<< ":" << len << "] == " << value << " )"
		filter << " and ";
		switch (next_layer->GetID()) {
			case TCP::PROTO: { /* Match ports or seq numbers */
				TCP *tcp = dynamic_cast<TCP*>(next_layer);
				filter << "( "
							"( "
							MATCH(0, 2, tcp->GetSrcPort()) " and "
							MATCH(2, 2, tcp->GetDstPort())
							") or ("
							MATCH(4, 4, tcp->GetSeqNumber()) " and "
							MATCH(8, 4, tcp->GetAckNumber())
							")"
						")"
					;
				}
				break;
			case UDP::PROTO: { /* Match ports */
				UDP *udp = dynamic_cast<UDP*>(next_layer);
				filter << MATCH(0, 2, udp->GetSrcPort()) " and "
					MATCH(2, 2, udp->GetDstPort());
				}
		   		break;
			default: /* Match first byte of next header */
				filter << MATCH(0, 1, (int)next_layer->raw_data[0]);
				break;
		}
#undef MATCH
	}
	filter <<		" ) " /* (same addresses and x) */
				")" /* icmp and (sth) */
			")"; /* or (icmp) */
}

template<>
IPLayer* Packet::GetLayer<IPLayer>() const {
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = begin() ; it_layer != end() ; ++it_layer)
		if ((*it_layer)->GetID() == IP::PROTO || (*it_layer)->GetID() == IPv6::PROTO)
			return dynamic_cast<IPLayer*>( (*it_layer) );
	/* No requested layer, returns zero */
	return 0;
}

template<>
ICMPLayer* Packet::GetLayer<ICMPLayer>() const {
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = begin() ; it_layer != end() ; ++it_layer)
		if ((*it_layer)->GetID() == ICMP::PROTO || (*it_layer)->GetID() == ICMPv6::PROTO)
			return dynamic_cast<ICMPLayer*>( (*it_layer) );
	/* No requested layer, returns zero */
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
