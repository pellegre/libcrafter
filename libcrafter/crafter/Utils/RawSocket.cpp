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


#include "RawSocket.h"
#include "PrintMessage.h"
#include "../Layer.h"
#include "../Protocols/IP.h"
#include "../Protocols/IPv6.h"

using namespace std;
using namespace Crafter;

map<string,vector<SocketSender::SocketCouple> > SocketSender::socket_table;

int SocketSender::RequestSocket(const std::string& iface, word proto_id) {
	string interface;
	/* First check if the string is not empty */
	if (iface.size() == 0) interface = "default";
	else interface = iface;

	/* Now check if the interface is on the map */
	map<string,vector<SocketCouple> >::iterator it = socket_table.find(interface);

	/* Raw socket */
	int raw;

	if(it != socket_table.end()) {
		/* A socket was binded to this interface, search for it */
		 vector<SocketCouple>::iterator it_sc;

		 for(it_sc = (*it).second.begin() ; it_sc != (*it).second.end() ; ++it_sc) {
			 if(proto_id == (*it_sc).protocol)
				 return (*it_sc).socket;
		 }
	}

	/* We should create a socket and bind it to the interface */
	if(proto_id == IP::PROTO) {

		/* Create a raw layer socket */
		raw = CreateRawSocket();

		/* If the user specify an interface, bind the socket to it */
		if(iface.size() > 0)
			BindRawSocketToInterface(interface.c_str(),raw);

	}

	else if(proto_id == IPv6::PROTO) {

		/* Create a raw layer socket */
		raw = CreateRaw6Socket();

		/* If the user specify an interface, bind the socket to it */
		if(iface.size() > 0)
			BindRawSocketToInterface(interface.c_str(),raw);

	}

	else {
		/* Create a link layer protocol */
		raw = CreateLinkSocket();

		/* If the user specify an interface, bind the socket to it */
		if(iface.size() > 0)
			BindLinkSocketToInterface(interface.c_str(),raw);

	}

	/* Create the socket couple */
	SocketCouple sc;
	sc.socket = raw;
	sc.protocol = proto_id;

	/* And push it into the global map */
	socket_table[interface].push_back(sc);
	return raw;
}

int Crafter::SocketSender::CreateLinkSocket(word protocol_to_sniff)
{
	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
	{
		Crafter::PrintMessage(Crafter::PrintCodes::PrintPerror,
				     "CreateLinkSocket()",
		             "Creating packet(PF_PACKET) socket");
		exit(1);
	}

	return rawsock;
}

int Crafter::SocketSender::CreateRawSocket(word protocol_to_sniff)
{
    /* Create a socket descriptor */
    int s = socket(PF_INET, SOCK_RAW, protocol_to_sniff);

    if(s < 0)
    {
		Crafter::PrintMessage(Crafter::PrintCodes::PrintPerror,
				     "CreateRawSocket()",
		             "Creating raw(PF_INET) socket");
		exit(1);
    }

    /* Sock options */
    int one = 1;
    const int* val = &one;

    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		PrintMessage(Crafter::PrintCodes::PrintError,
					"Packet::RawSocketSend()",
					"Setting IP_HDRINCL option to raw socket");
		exit(1);
	}

	if(setsockopt(s, SOL_SOCKET, SO_BROADCAST, val, sizeof(one)) < 0) {
		PrintMessage(Crafter::PrintCodes::PrintError,
					"Packet::RawSocketSend()",
					"Setting SO_BROADCAST flag to raw socket");
		exit(1);
	}

    return s;
}

int Crafter::SocketSender::CreateRaw6Socket(word protocol_to_sniff) {
    /* Create a socket descriptor */
    int s = socket(PF_INET6, SOCK_RAW, protocol_to_sniff);

    if(s < 0)
    {
		Crafter::PrintMessage(Crafter::PrintCodes::PrintPerror,
				     "CreateRawSocket()",
		             "Creating raw(PF_INET) socket");
		exit(1);
    }

    return s;
}

int Crafter::SocketSender::BindLinkSocketToInterface(const char *device, int rawsock, word protocol)
{

	struct sockaddr_ll sll;
	struct ifreq ifr;

	memset(&sll,0,sizeof(sll));
	memset(&ifr,0,sizeof(ifr));

	/* First Get the Interface Index  */
	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		Crafter::PrintMessage(Crafter::PrintCodes::PrintPerror,
				     "BindLinkSocketToInterface()",
		             "Getting Interface index");
		exit(1);
	}

	/* Bind our raw socket to this interface */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol);


	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		Crafter::PrintMessage(Crafter::PrintCodes::PrintPerror,
				     "BindLinkSocketToInterface()",
		             "Binding raw socket to interface");
		exit(1);
	}

	return 0;
}

int Crafter::SocketSender::BindRawSocketToInterface(const char *device, int s)
{
	/* Bind to interface */
    ifreq Interface;
    memset(&Interface, 0, sizeof(Interface));
    strncpy(Interface.ifr_ifrn.ifrn_name, device, IFNAMSIZ);
    if (ioctl(s, SIOCGIFINDEX, &Interface) < 0)
    {
		Crafter::PrintMessage(Crafter::PrintCodes::PrintPerror,
				     "BindRawSocketToInterface()",
		             "Binding raw socket to interface");
		exit(1);
    }

    return 0;
}

int Crafter::SocketSender::SendLinkSocket(int rawsock, byte *pkt, size_t pkt_len)
{
	return write(rawsock, pkt, pkt_len);
}

int Crafter::SocketSender::SendRawSocket(int rawsock, struct sockaddr* din, size_t size_dst, byte *pkt, size_t pkt_len)
{
	return sendto(rawsock, pkt, pkt_len, 0, din, size_dst);
}

int Crafter::SocketSender::SendSocket(int rawsock, word proto_id, byte *pkt, size_t pkt_len) {
	if(proto_id == IP::PROTO) {
		/* Raw socket, IPv4 */
		struct sockaddr_in din;
	    din.sin_family = AF_INET;
	    din.sin_port = 0;
	    memcpy(&din.sin_addr.s_addr,pkt + 16,sizeof(in_addr_t));
	    memset(din.sin_zero, '\0', sizeof (din.sin_zero));

	    return SendRawSocket(rawsock,(sockaddr *)&din,sizeof(din),pkt,pkt_len);
	}

	else if(proto_id == IPv6::PROTO) {
		/* Raw socket, IPv6 */
		struct sockaddr_in6 dest;
		dest.sin6_family = AF_INET6;
		memcpy(&dest.sin6_addr,pkt+24,16);
		dest.sin6_flowinfo = 0;
		dest.sin6_scope_id = 0;
		/* From kernel code, this should be zero for ipv6 raw sockets */
		dest.sin6_port = 0;

	    return SendRawSocket(rawsock,(struct sockaddr*)&dest,sizeof(dest),pkt,pkt_len);
	}

	return SendLinkSocket(rawsock,pkt,pkt_len);

}

Crafter::SocketSender::~SocketSender() {
	map<string,vector<SocketCouple> >::iterator it_iface;
	vector<SocketCouple>::iterator it_sc;
	/* Close all sockets */
	for(it_iface = socket_table.begin() ; it_iface != socket_table.end() ; ++it_iface) {
		for(it_sc = (*it_iface).second.begin() ; it_sc != (*it_iface).second.end() ; ++it_sc)
			close((*it_sc).socket);
	}
}

