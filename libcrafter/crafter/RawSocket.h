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


#ifndef RAWSOCKET_H_
#define RAWSOCKET_H_

#include<iostream>
#include<cstdio>
#include<cstdlib>
#include<sys/socket.h>
#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<cerrno>
#include<sys/ioctl.h>
#include<net/if.h>
#include<arpa/inet.h>
#include<cstring>
#include <unistd.h>

int CreateRawSocket(int protocol_to_sniff);

int BindRawSocketToInterface(const char *device, int rawsock, int protocol);

int SendRawPacket(int rawsock, unsigned char *pkt, int pkt_len);

#endif /* RAWSOCKET_H_ */
