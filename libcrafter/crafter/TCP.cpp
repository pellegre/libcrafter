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


#include "TCP.h"

using namespace std;
using namespace Crafter;

TCP::TCP() {
	/* Allocate five words */
	allocate_words(5);
	/* Name of the protocol represented by this layer */
	SetName("TCP");
	/* Set the protocol ID */
	SetprotoID(0x06);

	/* Creates field information for the layer */
	DefineProtocol();

	/* Always set default values for fields in a layer */
	SetSrcPort(0);
	SetDstPort(80);
	SetSeqNumber(0);
	SetAckNumber(0);
	SetDataOffset(5);
	SetReserved(0);
	SetFlags(0);
	SetWindowsSize(5840);
	SetCheckSum(0);
	SetUrgPointer(0);

	/* Always call this, reset all fields */
	ResetFields();
}

/* Copy crafted packet to buffer_data */
void TCP::Craft () {
	/* Get the layer on the bottom of this one, and verify that is an IP layer */
	IP* ip_layer = 0;
	/* Bottom layer name */
	Layer* bottom_ptr = GetBottomLayer();
	std::string bottom_layer = "";
	if(bottom_ptr)  bottom_layer = bottom_ptr->GetName();

	/* Checksum of UDP packet */
	short_word checksum;

	/* Check the options and update header length */
	size_t option_length = (GetSize() - GetHeaderSize())/4;

	if (option_length)
		if (!IsFieldSet("OffRes")) {
			SetDataOffset(5 + option_length);
			ResetField("OffRes");
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
			pseudo_header->SetProtocolLength(GetRemainingSize());

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
					     "TCP::Craft()",
				         "Top Layer of TCP packet is not IP. Cannot calculate TCP checksum.");
			checksum = 0;
		}

		SetCheckSum(ntohs(checksum));
		ResetField("CheckSum");
	}

}

void TCP::LibnetBuild(libnet_t* l) {
	/* Get the payload */
	size_t options_size = (GetDataOffset() - 5) * 4;
	byte* options = 0;

	if (options_size) {
		options = new byte[options_size];
		GetPayload(options);
	}	/* In case the header has options */


	if (options) {

		int opt  = libnet_build_tcp_options ( options,
											  GetPayloadSize(),
											  l,
											  0
											 );

		/* In case of error */
		if (opt == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "TCP::LibnetBuild()",
			             "Unable to build TCP options: " + string(libnet_geterror (l)));
			exit (1);
		}

	}

	int tcp = libnet_build_tcp ( GetSrcPort(),
			                     GetDstPort(),
			                     GetSeqNumber(),
			                     GetAckNumber(),
			                     GetFlags(),
			                     GetWindowsSize(),
			                     GetCheckSum(),
			                     GetUrgPointer(),
			                     GetSize(),
			                     NULL,
			                     0,
			                     l,
			                     0
			                   );

	/* In case of error */
	if (tcp == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "TCP::LibnetBuild()",
		             "Unable to build TCP header: " + string(libnet_geterror (l)));
		exit (1);
	}

	if(options)
		delete [] options;
}


void TCP::DefineProtocol() {
	/* Source Port number */
	define_field("SrcPort",new NumericField(0,0,15));
	define_field("DstPort",new NumericField(0,16,31));
	define_field("SeqNumber",new NumericField(1,0,31));
	define_field("AckNumber",new NumericField(2,0,31));
	define_field("OffRes",new BitField<byte,4,4>(3,0,7,"DataOffset","Reserved"));
	define_field("Flags", new ControlFlags(3,8,15));
	define_field("WindowsSize",new NumericField(3,16,31));
	define_field("CheckSum",new HexField(4,0,15));
	define_field("UrgPointer",new NumericField(4,16,31));
}

