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


#ifndef RAWSOCKET_H_
#define RAWSOCKET_H_

#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef __APPLE__
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#else
#define ETH_P_ALL 1
#endif

#include <cerrno>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>

#include "../Types.h"

namespace Crafter {

	class SocketSender {

		struct SocketCouple {
			word protocol;
			int socket;
		};

		/* Map of socket to each interface requested by the user (by protocol ID) */
		static std::map<std::string,std::vector<SocketCouple> > socket_table;

		/* Prevent construction of this object */
		SocketSender();
		SocketSender(SocketSender& cpy);

		/* Sockets in link layer */
		static int CreateLinkSocket(word protocol_to_sniff = ETH_P_ALL);
		static int BindLinkSocketToInterface(const char *device, int rawsock, word protocol = ETH_P_ALL);

		/* Raw sockets */
		static int CreateRawSocket(word protocol_to_sniff = IPPROTO_RAW);
		static int CreateRaw6Socket(word protocol_to_sniff = IPPROTO_RAW);
		static int BindRawSocketToInterface(const char *device, int rawsock);

		/* Write data on the wire */
		static int SendLinkSocket(int rawsock, byte *pkt, size_t pkt_len);
		static int SendRawSocket(int rawsock, struct sockaddr *din, size_t size_dst, byte *pkt, size_t pkt_len);

	public:

		/* Request a socket */
		static int RequestSocket(const std::string& iface, word proto_id);
		/* Write into a socket */
		static int SendSocket(int rawsock, word proto_id, byte *pkt, size_t pkt_len);

		~SocketSender();
	};
}

#endif /* RAWSOCKET_H_ */
