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
