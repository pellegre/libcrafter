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


#include "UDP.h"

using namespace Crafter;
using namespace std;

UDP::UDP() {
	/* Allocate two words */
	allocate_words(2);
	/* Name of the protocol represented by this layer */
	SetName("UDP");
	/* Set the protocol ID */
	SetprotoID(0x11);

	/* Creates field information for the layer */
	DefineProtocol();

	/* Always set default values for fields in a layer */
	SetSrcPort(0);
	SetDstPort(53);
	SetLength(0);
	SetCheckSum(0);

	/* Always call this, reset all fields */
	ResetFields();
}

void UDP::DefineProtocol() {
	/* Source Port number */
	define_field("SrcPort",new NumericField(0,0,15));
	define_field("DstPort",new NumericField(0,16,31));
	define_field("Length",new NumericField(1,0,15));
	define_field("CheckSum",new HexField(1,16,31));
}

/* Copy crafted packet to buffer_data */
void UDP::Craft () {
	/* Get the layer on the bottom of this one, and verify that is an IP layer */
	IP* ip_layer = 0;
	/* Bottom layer name */
	Layer* bottom_ptr = GetBottomLayer();
	std::string bottom_layer = "";
	if(bottom_ptr)  bottom_layer = bottom_ptr->GetName();

	/* Checksum of UDP packet */
	short_word checksum;

	/* Set the Length of the UDP packet */
	if (!IsFieldSet("Length")) {
		SetLength(GetRemainingSize());
		ResetField("Length");
	}

	if (!IsFieldSet("CheckSum")) {

		/* Set the checksum to zero */
		SetCheckSum(0x00);

		if(bottom_layer == "IP") {
			/* It's OK */
			ip_layer = dynamic_cast<IP*>(GetBottomLayer());

			/* Construct the Pseudo Header */
			IPSeudoHeader* pseudo_header = new IPSeudoHeader;

			pseudo_header->SetSourceIP(ip_layer->GetSourceIP());
			pseudo_header->SetDestinationIP(ip_layer->GetDestinationIP());
			pseudo_header->SetZeros(0x00);
			pseudo_header->SetProtocol(GetID());
			pseudo_header->SetProtocolLength(GetLength());

			/* Now, prepare the payload */
			byte* payload = new byte[GetRemainingSize()];

			/* Get the payload */
			size_t cpy_payload = GetData(payload);

			/* Put the payload into the pseudo header */
			pseudo_header->SetPayload(payload, cpy_payload);

			/* If the layer size is not multiple of 2, padd one more byte */
			byte padd = 0;
			if ((pseudo_header->GetSize() %2) != 0) pseudo_header->AddPayload(&padd,1);

			/* That's it. Now get the data and calculate the checksum */
			byte* data = new byte[pseudo_header->GetSize()];
			pseudo_header->GetData(data);

			/* 16 bit Checksum */
			checksum = CheckSum((unsigned short *)data,pseudo_header->GetSize()/2);

			delete pseudo_header;
			delete [] payload;
			delete [] data;

		} else {
			PrintMessage(Crafter::PrintCodes::PrintWarning,
					     "UDP::Craft()",
				         "Top Layer of UDP packet is not IP. Cannot calculate UDP checksum.");
			checksum = 0;
		}

		SetCheckSum(ntohs(checksum));
		ResetField("CheckSum");
	}
}

void UDP::LibnetBuild(libnet_t *l) {

	/* Get the payload */
	size_t payload_size = GetPayloadSize();
	byte* payload;

	if (payload_size) {
		payload = new byte[payload_size];
		GetPayload(payload);
	} else
		payload = 0;

	/* Now write the data into de libnet context */
	int udp = libnet_build_udp (  GetSrcPort(),
								  GetDstPort(),
								  GetLength(),
								  GetCheckSum(),
								  payload,
								  payload_size,
								  l,
								  0
							    );

	/* In case of error */
	if (udp == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "UDP::LibnetBuild()",
		             "Unable to build UDP header: " + string(libnet_geterror (l)));
		exit (1);
	}

	if(payload)
		delete [] payload;

}

