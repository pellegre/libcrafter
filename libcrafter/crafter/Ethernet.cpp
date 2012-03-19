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


#include "Ethernet.h"

using namespace Crafter;
using namespace std;

/* Destination MAC address byte fields names */
const string dst_ether_fields[Ethernet::n_ether_bytes] =
                                                  {
                                                    "DstMAC1",
		                                            "DstMAC2",
		                                            "DstMAC3",
		                                            "DstMAC4",
		                                            "DstMAC5",
		                                            "DstMAC6"
                                                   };

/* Source MAC address byte fields names */
const string src_ether_fields[Ethernet::n_ether_bytes] =
                                                  {
                                                    "SrcMAC1",
		                                            "SrcMAC2",
		                                            "SrcMAC3",
		                                            "SrcMAC4",
		                                            "SrcMAC5",
		                                            "SrcMAC6"
                                                   };

const std::string Ethernet::DefaultMAC = "00:00:00:00:00:00";

Ethernet::Ethernet() {
	/* Allocate 14 bytes */
	allocate_bytes(14);
	/* Name of the protocol represented by this layer */
	SetName("Ethernet");
	/* Set the protocol ID */
	SetprotoID(0xfff2);

	/* Creates field information for the layer */
	DefineProtocol();

	/* Always set default values for fields in a layer */
	SetDestinationMAC(DefaultMAC);
	SetSourceMAC(DefaultMAC);
	SetType(0x0800);

	/* Always call this, reset all fields */
	ResetFields();
}

/* Convert MAC address in string format to values for each field*/
void Ethernet::SrcMacStringToFields(const std::string& mac_address) {
	size_t ipos = 0;

	for(int i = 0 ; i < n_ether_bytes ; i++) {

		size_t epos = mac_address.find_first_of(":",ipos);
		string ether_byte = mac_address.substr(ipos,2);

		char* endptr;

		word byte_value = strtoul(ether_byte.c_str(),&endptr,16);
		SetFieldValue<word>(src_ether_fields[i],byte_value);

		ipos = epos + 1;
	}

}

void Ethernet::DstMacStringToFields(const std::string& mac_address) {
	size_t ipos = 0;

	for(int i = 0 ; i < n_ether_bytes ; i++) {

		size_t epos = mac_address.find_first_of(":",ipos);
		string ether_byte = mac_address.substr(ipos,2);

		char* endptr;

		word byte_value = strtoul(ether_byte.c_str(),&endptr,16);
		SetFieldValue<word>(dst_ether_fields[i],byte_value);

		ipos = epos + 1;
	}
}

/* Get values of each field an update MAC address */
std::string Ethernet::SrcMacFieldsToString() {
	string mac;
	int i = 0;
	char str[3] = {0};

	for(i = 0 ; i < n_ether_bytes ; i++) {
		short_word dst = GetFieldValue<word>(src_ether_fields[i]);;
		sprintf(str,"%.2x",dst);
		if (i < n_ether_bytes - 1)
			mac += string(str)+":";
		else
			mac += string(str);
	}

	return mac;
}

std::string Ethernet::DstMacFieldsToString() {
	string mac;
	int i = 0;
	char str[3] = {0};

	for(i = 0 ; i < n_ether_bytes ; i++) {
		short_word dst = GetFieldValue<word>(dst_ether_fields[i]);;
		sprintf(str,"%.2x",dst);
		if (i < n_ether_bytes - 1)
			mac += string(str)+":";
		else
			mac += string(str);
	}

	return mac;
}

void Ethernet::DefineProtocol() {
	/* Destination MAC number */
	define_field("DstMAC1",new NumericField(0,0,7));
	define_field("DstMAC2",new NumericField(0,8,15));
	define_field("DstMAC3",new NumericField(0,16,23));
	define_field("DstMAC4",new NumericField(0,24,31));
	define_field("DstMAC5",new NumericField(1,0,7));
	define_field("DstMAC6",new NumericField(1,8,15));
	/* Source MAC number */
	define_field("SrcMAC1",new NumericField(1,16,23));
	define_field("SrcMAC2",new NumericField(1,24,31));
	define_field("SrcMAC3",new NumericField(2,0,7));
	define_field("SrcMAC4",new NumericField(2,8,15));
	define_field("SrcMAC5",new NumericField(2,16,23));
	define_field("SrcMAC6",new NumericField(2,24,31));
	/* Type */
	define_field("Type",new HexField(3,0,15));
}

void Ethernet::Craft () {
	DestinationMAC = DstMacFieldsToString();
	SourceMAC = SrcMacFieldsToString();

	if(TopLayer) {
		if (!IsFieldSet("Type")) {
			std::string network_layer = TopLayer->GetName();
			/* Set Protocol */
			if(network_layer != "RawLayer")
				SetType(Protocol::AccessFactory()->GetProtoID(network_layer));
			else
				SetType(0x0);
			ResetField("Type");
		}
	}
	else
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Ethernet::Craft()","No Network Layer Protocol associated with Ethernet Layer.");
}

void Ethernet::ReDefineActiveFields() {
	DestinationMAC = DstMacFieldsToString();
	SourceMAC = SrcMacFieldsToString();
}

void Ethernet::LibnetBuild(libnet_t *l) {

	int r; /* Generic size */

	/* Put addresses on correct format */
	u_int8_t* src = libnet_hex_aton(SourceMAC.c_str(),&r);      /* Source hardware address */
	u_int8_t* dst = libnet_hex_aton(DestinationMAC.c_str(),&r); /* Destination hardware address */

	/* Get the payload */
	size_t payload_size = GetPayloadSize();
	byte* payload;
	if (payload_size) {
		payload = new byte[payload_size];
		GetPayload(payload);
	} else
		payload = 0;

	/* Now write the data into de libnet context */
	int eth = libnet_build_ethernet(  dst,
									  src,
									  GetType(),
									  payload,
									  payload_size,
									  l,
									  0
								    );

	/* In case of error */
	if (eth == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Ethernet::LibnetBuild()",
		             "Unable to build Ethernet header: " + string(libnet_geterror (l)));
		exit (1);
	}

	free(src); free(dst);
	if(payload)
		delete [] payload;

}

void Ethernet::Print() const{
	cout << "< ";
	cout << name << " (" << dec << GetSize() << " bytes) " << ":: ";

	cout << "Destination = " << GetDestinationMAC() << " ; ";
	cout << "Source = " << GetSourceMAC() << " ; ";
	cout << "Type = " << hex << GetType() << " ; ";

	cout << "Payload = ";
	LayerPayload.Print();

	cout << ">" << endl;
}

