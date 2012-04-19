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
				         "Bottom Layer of UDP packet is not IP. Cannot calculate UDP checksum.");
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

