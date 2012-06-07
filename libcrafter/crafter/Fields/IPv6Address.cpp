/*
 * IPv6Address.cpp
 *
 *  Created on: Jun 6, 2012
 *      Author: larry
 */

#include "IPv6Address.h"
#include "../Utils/IPResolver.h"
#include <arpa/inet.h>

using namespace std;
using namespace Crafter;

IPv6Address::IPv6Address(const std::string& name, size_t nword, size_t nbyte) :
					     Field<std::string> (name,nword,nbyte*8,48),
					     nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

void IPv6Address::SetField(const string& ip_address) {
	if(!validateIpv6Address(ip_address))
		human = GetIPv6(ip_address);
	else
		human = ip_address;
}


void IPv6Address::Write(byte* raw_data) const {
	inet_pton(AF_INET6, human.c_str(), raw_data + offset);
}

void IPv6Address::Read(const byte* raw_data) {
	struct sockaddr_in6 addr;
	memcpy(&addr.sin6_addr, raw_data + offset, sizeof(struct in6_addr));
	char addressBuffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr.sin6_addr, addressBuffer, INET6_ADDRSTRLEN);
    human = string(addressBuffer);
}

FieldInfo* IPv6Address::Clone() const {
	IPv6Address* new_ptr = new IPv6Address(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

void IPv6Address::Print(std::ostream& str) const {
	str << GetName() << " = " << human;
}

IPv6Address::~IPv6Address() { /* */ }
