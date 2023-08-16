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

#include <stdexcept>

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
			BindRawSocketToInterface(interface,raw);

	}

	else if(proto_id == IPv6::PROTO) {
#ifdef _UNIX_COMPAT_
		/* FreeBSD/Mac OSX does not allow the IP_HDRINCL option
		 * on RAW IPv6 sockets. We therefore create a LL socket
		 * that will build the correct Ethernet header when sending
		 * packets.
		 */
		raw = CreateLinkSocket();

		/* If the user specify an interface, bind the socket to it */
		if(iface.size() > 0)
			BindLinkSocketToInterface(interface.c_str(),raw);
#else
		/* Create a raw layer socket */
		raw = CreateRaw6Socket();

		/* If the user specify an interface, bind the socket to it */
		if(iface.size() > 0)
			BindRawSocketToInterface(interface,raw);
#endif

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

#ifdef _UNIX_COMPAT_
	int i;

	for (i = 0; i < 128; i++) {
		char file[32];

		snprintf(file, sizeof(file), "/dev/bpf%d", i);
		rawsock = open(file, O_WRONLY);
		if (rawsock != -1 || errno != EBUSY)
			break;
	}
#else
	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1) {
		perror("CreateLinkSocket()");
		throw std::runtime_error("Creating packet(PF_PACKET) socket");
	}
#endif

	return rawsock;
}

int Crafter::SocketSender::CreateRawSocket(word protocol_to_sniff)
{
    /* Create a socket descriptor */
    int s = socket(PF_INET, SOCK_RAW, protocol_to_sniff);

    if(s < 0) {
    	perror("CreateRawSocket()");
		throw std::runtime_error("Creating raw(PF_INET) socket");
    }

    /* Sock options */
    int one = 1;
    const int* val = &one;

    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    	perror("CreateRawSocket()");
		throw std::runtime_error("Setting IP_HDRINCL option to raw socket");
    }

	if(setsockopt(s, SOL_SOCKET, SO_BROADCAST, val, sizeof(one)) < 0) {
    	perror("CreateRawSocket()");
		throw std::runtime_error("Setting SO_BROADCAST flag to raw socket");
	}

    return s;
}

int Crafter::SocketSender::CreateRaw6Socket(word protocol_to_sniff) {
    /* Create a socket descriptor */
    int s = socket(PF_INET6, SOCK_RAW, protocol_to_sniff);

    if(s < 0) {
    	perror("CreateRaw6Socket()");
		throw std::runtime_error("Creating raw(PF_INET) socket");
    }

    return s;
}

int Crafter::SocketSender::BindLinkSocketToInterface(const char *device, int rawsock, word protocol)
{
	struct ifreq ifr;


#ifdef _UNIX_COMPAT_
	int i;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(rawsock, BIOCSETIF, (char *)&ifr) < 0) {
		perror("BindLinkSocketToInterface()");
		throw std::runtime_error("Binding raw socket to interface");
	}
#ifdef BIOCSHDRCMPLT
	i = 1;
	if (ioctl(rawsock, BIOCSHDRCMPLT, &i) < 0) {
		perror("BindLinkSocketToInterface()");
		throw std::runtime_error("Binding raw socket to interface");
	}
#endif

#else
	struct sockaddr_ll sll;

	memset(&sll,0,sizeof(sll));
	memset(&ifr,0,sizeof(ifr));

	/* First Get the Interface Index  */
	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1) {
		perror("BindLinkSocketToInterface()");
		throw std::runtime_error("Getting Interface index");
	}

	/* Bind our raw socket to this interface */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol);


	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1) {
		perror("BindLinkSocketToInterface()");
		throw std::runtime_error("Binding raw socket to interface");
	}
#endif
	return 0;
}

int Crafter::SocketSender::BindRawSocketToInterface(const std::string &device,
		int s)
{
	/* Bind to interface */
#ifndef _UNIX_COMPAT_
	/* See man 7 raw */
	setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, device.c_str(), device.size());
#endif
    return 0;
}

int Crafter::SocketSender::SendLinkSocket(int rawsock, byte *pkt, size_t pkt_len)
{
	return write(rawsock, pkt, pkt_len);
}

int Crafter::SocketSender::SendRawSocket(int rawsock, struct sockaddr* din, size_t size_dst, byte *pkt, size_t pkt_len)
{
	int ret;

	ret = sendto(rawsock, pkt, pkt_len, 0, din, size_dst);
	if (ret < 0)
		perror("sendto");
	return ret;
}

#ifdef _UNIX_COMPAT_
/* Resolve IPv6 destination address -> MAC address of gateway */

#define NEXTSA(s) \
	((struct sockaddr *)((u_char *)(s) + (s)->sa_len))

static int
route6_get(const struct in6_addr *dst, struct in6_addr *gw)
{
	int fd;
	struct rt_msghdr *rtm;
	struct sockaddr *sa;
	struct sockaddr_in6 *sin6;
	u_char buf[BUFSIZ];
	pid_t pid = getpid();
	static int seq = 0;
	int len, i;

	memset(buf, 0, sizeof(buf));
	rtm = (struct rt_msghdr *) buf;

	rtm->rtm_type = RTM_GET;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_flags = RTF_UP;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_seq = ++seq;

	sa = (struct sockaddr *)(rtm + 1);
	sin6 = (struct sockaddr_in6 *)sa;

	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_family = AF_INET6;
	memcpy(&sin6->sin6_addr, dst, sizeof(*dst));
	sa = NEXTSA(sa);

	if (IN6_ARE_ADDR_EQUAL(dst, &in6addr_any)) {
		sin6 = (struct sockaddr_in6 *)sa;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		rtm->rtm_addrs |= RTA_NETMASK;
		sa = NEXTSA(sa);
	} else
		rtm->rtm_flags |= RTF_HOST;

	rtm->rtm_msglen = (u_char *)sa - buf;

	if ((fd = socket(PF_ROUTE, SOCK_RAW, AF_INET6)) < 0)
		return -1;

	if (write(fd, buf, rtm->rtm_msglen) < 0)
		return -1;

	while ((len = read(fd, buf, sizeof(buf))) > 0) {
		if (len < (int)sizeof(*rtm))
			return -1;
		if (rtm->rtm_type == RTM_GET && rtm->rtm_pid == pid &&
		    rtm->rtm_seq == seq) {
			if (rtm->rtm_errno) {
				errno = rtm->rtm_errno;
				return -1;
			}
			break;
		}
	}

	sa = (struct sockaddr *)(rtm + 1);
	if (rtm->rtm_addrs) {
		for (i = 1; i; i <<= 1) {
			if (i & rtm->rtm_addrs) {
				if (i == RTA_GATEWAY && rtm->rtm_flags & RTF_GATEWAY) {
					sin6 = (struct sockaddr_in6 *)sa;
					memcpy(gw, &sin6->sin6_addr, sizeof(*gw));
					goto out;
				}
				sa = NEXTSA(sa);
			}
		}
	}

out:
	close(fd);
	return 0;
}

static int
route6_ether(const struct in6_addr *addr, u_char *lladdr)
{
	int fd;
	struct rt_msghdr *rtm;
	struct sockaddr *sa;
	struct sockaddr_in6 *sin6;
	struct sockaddr_dl *sdl;
	u_char buf[BUFSIZ];
	pid_t pid = getpid();
	static int seq = 0;
	int len, i;

	memset(buf, 0, sizeof(buf));
	rtm = (struct rt_msghdr *) buf;

	rtm->rtm_type = RTM_GET;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_flags = RTF_LLINFO;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_seq = ++seq;

	sa = (struct sockaddr *)(rtm + 1);
	sin6 = (struct sockaddr_in6 *)sa;

	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_family = AF_INET6;
	memcpy(&sin6->sin6_addr, addr, sizeof(*addr));
	sa = NEXTSA(sa);

	rtm->rtm_msglen = (u_char *)sa - buf;

	if ((fd = socket(PF_ROUTE, SOCK_RAW, AF_INET6)) < 0)
		return -1;

	if (write(fd, buf, rtm->rtm_msglen) < 0)
		return -1;

	while ((len = read(fd, buf, sizeof(buf))) > 0) {
		if (len < (int)sizeof(*rtm))
			return -1;
		if (rtm->rtm_type == RTM_GET && rtm->rtm_pid == pid &&
		    rtm->rtm_seq == seq) {
			if (rtm->rtm_errno) {
				errno = rtm->rtm_errno;
				return -1;
			}
			break;
		}
	}

	sa = (struct sockaddr *)(rtm + 1);
	if (rtm->rtm_addrs) {
		for (i = 1; i; i <<= 1) {
			if (i & rtm->rtm_addrs) {
				if(sa->sa_family == AF_LINK)
					goto found;
				sa = NEXTSA(sa);
			}
		}
		goto out;
	}

found:
	sdl = (struct sockaddr_dl *)sa;
	memcpy(lladdr, &sdl->sdl_data, sdl->sdl_alen);
out:
	close(fd);
	return 0;
}

static int
route6_get_ether(struct in6_addr *dst, u_char *lladdr)
{
	struct in6_addr gw;
	memset(&gw, 0, sizeof(gw));
	if (route6_get(&in6addr_any, &gw) < 0)
		return -1;
	if (route6_ether(&gw, lladdr) < 0)
		return -1;

	return 0;
}

#endif

int Crafter::SocketSender::SendSocket(int rawsock, word proto_id, byte *pkt, size_t pkt_len) {
	if(proto_id == IP::PROTO) {
		/* Raw socket, IPv4 */
		struct sockaddr_in din;
	    din.sin_family = AF_INET;
	    din.sin_port = 0;
	    memcpy(&din.sin_addr.s_addr,pkt + 16,sizeof(din.sin_addr.s_addr));
	    memset(din.sin_zero, '\0', sizeof (din.sin_zero));

	    return SendRawSocket(rawsock,(sockaddr *)&din,sizeof(din),pkt,pkt_len);
	}

	else if(proto_id == IPv6::PROTO) {
#ifdef _UNIX_COMPAT_
		/* We need to build a complete Ethernet header*/
		struct llhdr {
			u_char dst[6];
			u_char src[6];
			u_short proto;
		} __attribute__((packed)) *ether;
		byte *new_pkt = new byte[pkt_len + sizeof(*ether)];
		struct in6_addr addr;

		ether = (struct llhdr *)new_pkt;
		ether->proto = htons(proto_id);

		memcpy(&addr, pkt+24, 16);
		route6_get_ether(&addr, ether->dst);
		memcpy(&addr, pkt+8, 16);
		route6_ether(&addr, ether->src);

		memcpy(new_pkt + sizeof(*ether), pkt, pkt_len);
		return SendLinkSocket(rawsock, new_pkt, pkt_len + sizeof(*ether));
#else
		/* Raw socket, IPv6 */
		struct sockaddr_in6 dest;
		dest.sin6_family = AF_INET6;
		memcpy(&dest.sin6_addr,pkt+24,16);
		dest.sin6_flowinfo = 0;
		dest.sin6_scope_id = 0;
		/* From kernel code, this should be zero for ipv6 raw sockets */
		dest.sin6_port = 0;

	    return SendRawSocket(rawsock,(struct sockaddr*)&dest,sizeof(dest),pkt,pkt_len);
#endif

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

