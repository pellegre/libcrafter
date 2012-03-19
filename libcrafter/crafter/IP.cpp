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


#include "IP.h"

using namespace std;
using namespace Crafter;

const std::string IP::DefaultIP = "127.0.0.1";

IP::IP() {
		/* Allocate 5 words */
		allocate_words(5);
		/* Name of the protocol */
		SetName("IP");
		/* Set protocol NUmber */
		SetprotoID(0x0800);

		/* Creates field information for the layer */
		DefineProtocol();

		/* Always set default values for fields in a layer */
		SetVersion(4);
		SetHeaderLength(5);
		SetDifSerCP(0);
		SetTotalLength(0);
		SetIdentification(0);
		SetFlags(0x02);
		SetFragmentOffset(0);
		SetTTL(64);
		SetProtocol(0x06);
		SetCheckSum(0);

		/* Set default IP Addresses */
		SetSourceIP(DefaultIP);
		SetDestinationIP(DefaultIP);

		/* Always call this, reset all fields */
		ResetFields();
}

void IP::DefineProtocol() {
	/* Fields of the IP layer */
	define_field("VerHdr",new BitField<byte,4,4>(0,0,7,"Version","HeaderLength"));

	/* TODO : Fix this stuff */
	define_field("DifSerCP",new NumericField(0,8,15));
//	define_field("ExplicitCongNot",new NumericField(0,14,15));

	define_field("TotalLength",new NumericField(0,16,31));
	define_field("Identification",new HexField(1,0,15));
	define_field("Off",new BitField<short_word,3,13>(1,16,31,"Flags","FragmentOffset"));
	define_field("TTL",new NumericField(2,0,7));
	define_field("Protocol",new HexField(2,8,15));
	define_field("CheckSum",new HexField(2,16,31));
	define_field("SourceIP",new IPAddress(3,0,31));
	define_field("DestinationIP",new IPAddress(4,0,31));
}

void IP::Craft () {
	size_t tot_length = GetRemainingSize();
	/* First, put the total length on the header */
	if (!IsFieldSet("TotalLength")) {
		SetTotalLength(tot_length);
		ResetField("TotalLength");
	}

	/* Get transport layer protocol */
	if(TopLayer) {
		if(!IsFieldSet("Protocol")) {
			std::string transport_layer = TopLayer->GetName();
			/* Set Protocol */
			if(transport_layer != "RawLayer")
				SetProtocol(Protocol::AccessFactory()->GetProtoID(transport_layer));
			else
				SetProtocol(0x0);

			ResetField("Protocol");
		}
	}
	else {
		if (ShowWarnings)
			std::cerr << "[!] WARNING: No Transport Layer Protocol asociated with IP Layer. " << std::endl;
	}

	/* Check the options and update header length */
	size_t option_length = (GetSize() - GetHeaderSize())/4;
	if (option_length)
		if (!IsFieldSet("VerHdr")) {
			SetHeaderLength(5 + option_length);
			ResetField("VerHdr");
		}

	if (!IsFieldSet("CheckSum")) {
		/* Compute the 16 bit checksum */
		SetCheckSum(0);
		byte* buffer = new byte[GetSize()];
		GetRawData(buffer);
		/* Calculate the checksum */
		short_word checksum = CheckSum((unsigned short *)buffer,GetSize()/2);
		SetCheckSum(ntohs(checksum));
		delete [] buffer;
		ResetField("CheckSum");
	}
}

void IP::LibnetBuild(libnet_t *l) {

	in_addr_t src = inet_addr(GetSourceIP().c_str());           /* Source protocol address */
	in_addr_t dst = inet_addr(GetDestinationIP().c_str());      /* Destination protocol address */

	/* Get the payload */
	size_t options_size = (GetHeaderLength() - 5) * 4;
	byte* options = 0;

	if (options_size) {
		options = new byte[options_size];
		GetPayload(options);
	}

	struct FlagPack {
		short_word fieldh:13, fieldl:3;
	} flag_off;

	flag_off.fieldl = GetFlags();
	flag_off.fieldh = GetFragmentOffset();

	short_word* flag_off_pack = new short_word;

	memcpy((void*)flag_off_pack,(const void*)&flag_off,sizeof(FlagPack));

	/* In case the header has options */
	if (options) {
		int opt  = libnet_build_ipv4_options (options,
				                              options_size,
											  l,
											  0
											  );

		/* In case of error */
		if (opt == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "IP::LibnetBuild()",
			             "Unable to build IP options: " + string(libnet_geterror (l)));
			exit (1);
		}
	}

	/* Now write the data into de libnet context */
	int ip  = libnet_build_ipv4 ( GetTotalLength(),
			                      GetDifSerCP(),
			                      GetIdentification(),
			                      *flag_off_pack,
			                      GetTTL(),
			                      GetProtocol(),
			                      GetCheckSum(),
			                      src,
                                  dst,
								  NULL,
								  0,
								  l,
								  0
							    );

	/* In case of error */
	if (ip == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "IP::LibnetBuild()",
		             "Unable to build IP header: " + string(libnet_geterror (l)));
		exit (1);
	}

	if(options)
		delete [] options;

	delete flag_off_pack;

}

IPAddress::~IPAddress() {}
