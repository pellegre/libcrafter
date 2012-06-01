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


#include "IPSeudoHeader.h"

using namespace std;
using namespace Crafter;

IPSeudoHeader::IPSeudoHeader() {
	/* Allocate 5 words */
	allocate_words(3);
	/* Name of the protocol */
	SetName("IPSeudoHeader");
	/* Set protocol Number */
	SetprotoID(0xfff0);

	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(this);

	/* Creates field information for the layer */
	DefineProtocol();

	/* Get Local IP Address */
	struct in_addr local_address;
	local_address.s_addr = INADDR_ANY;
	string ip(inet_ntoa (local_address));
	SetSourceIP(ip);
	SetDestinationIP("127.0.0.1");

	/* Always set default values for fields in a layer */
	SetZeros(0x00);
	SetProtocol(0x06);
	SetProtocolLength(0);

	/* Always call this, reset all fields */
	ResetFields();
}

void IPSeudoHeader::DefineProtocol() {
	/* Fields of the IP Pseudo Header */
	define_field("SourceIP",new IPAddress(0,0,31));
	define_field("DestinationIP",new IPAddress(1,0,31));
	define_field("Zeros",new NumericField(2,0,7));
	define_field("Protocol",new NumericField(2,8,15));
	define_field("ProtocolLength",new NumericField(2,16,31));
}
