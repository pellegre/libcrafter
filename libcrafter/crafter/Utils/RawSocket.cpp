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

using namespace std;

int Crafter::CreateLinkSocket(int protocol_to_sniff)
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

int Crafter::CreateRawSocket(int protocol_to_sniff)
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

int Crafter::BindLinkSocketToInterface(const char *device, int rawsock, int protocol)
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

int Crafter::BindRawSocketToInterface(const char *device, int s)
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

int Crafter::SendLinkSocket(int rawsock, unsigned char *pkt, int pkt_len)
{
	return write(rawsock, pkt, pkt_len);
}

int Crafter::SendRawSocket(int rawsock, struct sockaddr* din, unsigned char *pkt, int pkt_len)
{
	return sendto(rawsock, pkt, pkt_len, 0, din, sizeof(struct sockaddr));
}
