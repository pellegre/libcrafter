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
