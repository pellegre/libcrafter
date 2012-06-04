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

#include <netinet/ether.h>
#include <cstdio>
#include "MACAddress.h"

using namespace std;
using namespace Crafter;

MACAddress::MACAddress(const std::string& name, size_t nword, size_t nbyte) :
					 Field<std::string> (name,nword,nbyte*8,48),
					 nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

void MACAddress::Write(byte* raw_data) const {
	struct ether_addr * ptr = (struct ether_addr *) (raw_data + offset);
	ether_aton_r(human.c_str(),ptr);
}

void MACAddress::Read(const byte* raw_data) {
	const struct ether_addr * ptr = (const struct ether_addr *) (raw_data + offset);
	char buf[19];
	  sprintf (buf, "%02x:%02x:%02x:%02x:%02x:%02x",
			  ptr->ether_addr_octet[0], ptr->ether_addr_octet[1],
			  ptr->ether_addr_octet[2], ptr->ether_addr_octet[3],
			  ptr->ether_addr_octet[4], ptr->ether_addr_octet[5]);
	buf[18] = 0;
	human = string(buf);
}

FieldInfo* MACAddress::Clone() const {
	MACAddress* new_ptr = new MACAddress(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

void MACAddress::Print(std::ostream& str) const {
	str << GetName() << " = " << human;
}

MACAddress::~MACAddress() { /* */ }
