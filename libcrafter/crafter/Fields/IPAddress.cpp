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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../Utils/IPResolver.h"

#include "IPAddress.h"

using namespace std;
using namespace Crafter;

IPAddress::IPAddress(const std::string& name, size_t nword, size_t nbyte) :
					 Field<std::string> (name,nword,nbyte*8,8*sizeof(word)),
					 nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

void IPAddress::SetField(const string& ip_address) {
	if(!validateIpv4Address(ip_address))
		human = GetIP(ip_address);
	else
		human = ip_address;
}

void IPAddress::Write(byte* raw_data) const {
	word* ptr = (word*) (raw_data + offset);
	*ptr = inet_addr(human.c_str());
}

void IPAddress::Read(const byte* raw_data) {
    struct sockaddr_in local_address;
	memcpy(&local_address.sin_addr, raw_data + offset, sizeof(struct in_addr));
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_address.sin_addr, str, INET_ADDRSTRLEN);
	human = string(str);
}

FieldInfo* IPAddress::Clone() const {
	IPAddress* new_ptr = new IPAddress(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

void IPAddress::Print(std::ostream& str) const {
	str << GetName() << " = " << human;
}

IPAddress::~IPAddress() { /* */ }

