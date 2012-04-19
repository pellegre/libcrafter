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

#include "DHCP.h"

using namespace std;
using namespace Crafter;

/* Destination MAC address byte fields names */
const string client_ether_fields[DHCP::n_ether_bytes] =
                                                  {
                                                    "ClientMAC1",
		                                            "ClientMAC2",
		                                            "ClientMAC3",
		                                            "ClientMAC4",
		                                            "ClientMAC5",
		                                            "ClientMAC6"
                                                   };

void DHCP::MacStringToFields(const std::string& mac_address) {
	size_t ipos = 0;

	for(int i = 0 ; i < n_ether_bytes ; i++) {

		size_t epos = mac_address.find_first_of(":",ipos);
		string ether_byte = mac_address.substr(ipos,2);

		char* endptr;

		word byte_value = strtoul(ether_byte.c_str(),&endptr,16);
		SetFieldValue<word>(client_ether_fields[i],byte_value);

		ipos = epos + 1;
	}
}

/* Get values of each field an update MAC address */
std::string DHCP::MacFieldsToString() {
	string mac;
	int i = 0;
	char str[3] = {0};

	for(i = 0 ; i < n_ether_bytes ; i++) {
		short_word dst = GetFieldValue<word>(client_ether_fields[i]);;
		sprintf(str,"%.2x",dst);
		if (i < n_ether_bytes - 1)
			mac += string(str)+":";
		else
			mac += string(str);
	}

	return mac;
}

DHCP::DHCP() {
	/* Allocate bytes */
	allocate_bytes(240);
	/* Name of the protocol represented by this layer */
	SetName("DHCP");
	/* Set the protocol ID */
	SetprotoID(0xfff4);

	/* Creates field information for the layer */
	DefineProtocol();

	/* Always set default values for fields in a layer */
	SetOperationCode(0);
	SetHardwareType(1);
	SetHardwareLength(6);
	SetHopCount(0);
	SetTransactionID(0);
	SetNumberOfSeconds(0);
	SetFlags(0x8000);
	SetClientIP("0.0.0.0");
	SetYourIP("0.0.0.0");
	SetServerIP("0.0.0.0");
	SetGatewayIP("0.0.0.0");
	SetClientMAC("ff:ff:ff:ff:ff:ff");
	ServerHostName = "";
	BootFileName = "";
}

void DHCP::DefineProtocol() {
	define_field("OperationCode",new NumericField(0,0,7));

	/* TODO - For now, just MAC addresses */
	define_field("HardwareType",new NumericField(0,8,15));
	define_field("HardwareLength",new NumericField(0,16,23));

	define_field("HopCount",new NumericField(0,24,31));
	define_field("TransactionID",new HexField(1,0,31));
	define_field("NumberOfSeconds",new HexField(2,0,15));
	define_field("Flags",new NumericField(2,16,31));
	define_field("ClientIP",new IPAddress(3,0,31));
	define_field("YourIP",new IPAddress(4,0,31));
	define_field("ServerIP",new IPAddress(5,0,31));
	define_field("GatewayIP",new IPAddress(6,0,31));
	define_field("ClientMAC1",new NumericField(7,0,7));
	define_field("ClientMAC2",new NumericField(7,8,15));
	define_field("ClientMAC3",new NumericField(7,16,23));
	define_field("ClientMAC4",new NumericField(7,24,31));
	define_field("ClientMAC5",new NumericField(8,0,7));
	define_field("ClientMAC6",new NumericField(8,8,15));
}

void DHCP::Craft() {
	/* 34 byte to reach the zero padding */
	size_t zero_pad_macaddr = 34;
	/* 44 bytes to reach the server host name */
	size_t servername_shift = 44;
	/* 108 bytes to reach the file boot name*/
	size_t filename_shift = 108;
	/* 236 bytes to reach the Magic Cookie*/
	size_t magicookie_shift = 236;

	/* Set the zero padding */
	/* TODO - For now, just MAC addresses */
	memset(raw_data + zero_pad_macaddr,0,magicookie_shift-zero_pad_macaddr);

	/* Copy the server host name into the data buffer */
	byte* server_ptr = raw_data + servername_shift;
	for(size_t i = 0; (i < ServerHostName.size()) && (i < (filename_shift - servername_shift)) ; i++)
		server_ptr[i] = ServerHostName[i];

	/* Copy the boot file name into the data buffer */
	byte* boot_ptr = raw_data + filename_shift;
	for(size_t i = 0; (i < BootFileName.size()) && (i < (magicookie_shift - filename_shift)) ; i++)
		boot_ptr[i] = BootFileName[i];

	/* Put the magic cookie */
	raw_data[magicookie_shift] = 0x63;
	raw_data[magicookie_shift + 1] = 0x82;
	raw_data[magicookie_shift + 2] = 0x53;
	raw_data[magicookie_shift + 3] = 0x63;

	std::vector<DHCPOptions*>::const_iterator it_opt;

	for(it_opt = Options.begin() ; it_opt != Options.end() ; it_opt++) {
		AddPayload((*it_opt)->GetData());
	}

	/* Put the end of options byte */
	byte padd = 0xff;
	AddPayload((const byte*)&padd,sizeof(byte));

}

void DHCP::LibnetBuild(libnet_t* l) {
	/* Get the payload */
	size_t payload_size = GetPayloadSize();
	byte* payload;

	if (payload_size) {
		payload = new byte[payload_size];
		GetPayload(payload);
	} else
		payload = 0;

	/* IP addresses */
	in_addr_t cip = inet_addr(GetClientIP().c_str());
	in_addr_t yip = inet_addr(GetYourIP().c_str());
	in_addr_t sip = inet_addr(GetServerIP().c_str());
	in_addr_t gip = inet_addr(GetGatewayIP().c_str());
	/* Client MAC address */
	int r;
	u_int8_t* macaddr = libnet_hex_aton(ClientMAC.c_str(),&r);
	u_int8_t* chaddr = new u_int8_t[16];
	memset(chaddr,0,16);
	memcpy(chaddr,macaddr,6);

	/* Server host name and boot file */
	/* 44 bytes to reach the server host name */
	size_t servername_shift = 44;
	/* 108 bytes to reach the file boot name*/
	size_t filename_shift = 108;
	/* Now write the data into de libnet context */
	int dhcp = libnet_build_dhcpv4 (
			  	                    GetOperationCode(),
				                    GetHardwareType(),
				                    GetHardwareLength(),
				                    GetHopCount(),
				                    GetTransactionID(),
				                    GetNumberOfSeconds(),
				                    GetFlags(),
				                    htonl(cip),
				                    htonl(yip),
				                    htonl(sip),
				                    htonl(gip),
				                    chaddr,
				                    raw_data + servername_shift,
				                    raw_data + filename_shift,
			                        payload,
								    payload_size,
								    l,
								    0
							      );

	/* In case of error */
	if (dhcp == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "DHCP::LibnetBuild()",
		             "Unable to build DHCP header: " + string(libnet_geterror (l)));
		exit (1);
	}

	if(payload)
		delete [] payload;

}

DHCP::~DHCP() {
	/* Delete the Options */
	std::vector<DHCPOptions*>::const_iterator it_opt;

	for(it_opt = Options.begin() ; it_opt != Options.end() ; it_opt++)
		delete (*it_opt);
}

