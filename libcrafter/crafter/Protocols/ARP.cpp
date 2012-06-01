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

#include "ARP.h"

using namespace Crafter;
using namespace std;

/* Destination MAC address byte fields names */
const string trg_ether_fields[ARP::n_ether_bytes] =
                                                  {
                                                    "TrgMAC1",
		                                            "TrgMAC2",
		                                            "TrgMAC3",
		                                            "TrgMAC4",
		                                            "TrgMAC5",
		                                            "TrgMAC6"
                                                   };

/* Source MAC address byte fields names */
const string snd_ether_fields[ARP::n_ether_bytes] =
                                                  {
                                                    "SndMAC1",
		                                            "SndMAC2",
		                                            "SndMAC3",
		                                            "SndMAC4",
		                                            "SndMAC5",
		                                            "SndMAC6"
                                                   };

const std::string ARP::DefaultIP = "127.0.0.1";
const std::string ARP::DefaultMAC = "00:00:00:00:00:00";

ARP::ARP() {
	/* Allocate bytes */
	allocate_bytes(28);
	/* Name of the protocol represented by this layer */
	SetName("ARP");
	/* Set the protocol ID */
	SetprotoID(0x0806);

	/* Creates field information for the layer */
	DefineProtocol();

	/* Always set default values for fields in a layer */
	SetTargetMAC(DefaultMAC);
	SetTargetIP(DefaultIP);
	SetSenderMAC(DefaultMAC);
	SetSenderIP(DefaultIP);
	SetHardwareType(0x1);
	SetProtocolType(0x0800);
	SetHardwareLength(0x6);
	SetProtocolLength(0x4);
	SetOperation(0x1);

	/* Always call this, reset all fields */
	ResetFields();
}

/* Convert MAC address in string format to values for each field*/
void ARP::SndMacStringToFields(const std::string& mac_address) {
	size_t ipos = 0;

	for(int i = 0 ; i < n_ether_bytes ; i++) {

		size_t epos = mac_address.find_first_of(":",ipos);
		string ether_byte = mac_address.substr(ipos,2);

		char* endptr;

		word byte_value = strtoul(ether_byte.c_str(),&endptr,16);
		SetFieldValue<word>(snd_ether_fields[i],byte_value);

		ipos = epos + 1;
	}

}

void ARP::TrgMacStringToFields(const std::string& mac_address) {
	size_t ipos = 0;

	for(int i = 0 ; i < n_ether_bytes ; i++) {

		size_t epos = mac_address.find_first_of(":",ipos);
		string ether_byte = mac_address.substr(ipos,2);

		char* endptr;

		word byte_value = strtoul(ether_byte.c_str(),&endptr,16);
		SetFieldValue<word>(trg_ether_fields[i],byte_value);

		ipos = epos + 1;
	}
}

/* Get values of each field an update MAC address */
std::string ARP::SndMacFieldsToString() {
	string mac;
	int i = 0;
	char str[3] = {0};

	for(i = 0 ; i < n_ether_bytes ; i++) {
		short_word dst = GetFieldValue<word>(snd_ether_fields[i]);;
		sprintf(str,"%.2x",dst);
		if (i < n_ether_bytes - 1)
			mac += string(str)+":";
		else
			mac += string(str);
	}

	return mac;
}

std::string ARP::TrgMacFieldsToString() {
	string mac;
	int i = 0;
	char str[3] = {0};

	for(i = 0 ; i < n_ether_bytes ; i++) {
		short_word dst = GetFieldValue<word>(trg_ether_fields[i]);;
		sprintf(str,"%.2x",dst);
		if (i < n_ether_bytes - 1)
			mac += string(str)+":";
		else
			mac += string(str);
	}

	return mac;
}

void ARP::DefineProtocol() {
	define_field("HardwareType",new NumericField(0,0,15));
	define_field("ProtocolType",new NumericField(0,16,31));
	define_field("HardwareLength",new NumericField(1,0,7));
	define_field("ProtocolLength",new NumericField(1,8,15));
	define_field("Operation",new NumericField(1,16,31));
	/* Sender MAC number */
	define_field("SndMAC1",new NumericField(2,0,7));
	define_field("SndMAC2",new NumericField(2,8,15));
	define_field("SndMAC3",new NumericField(2,16,23));
	define_field("SndMAC4",new NumericField(2,24,31));
	define_field("SndMAC5",new NumericField(3,0,7));
	define_field("SndMAC6",new NumericField(3,8,15));
	define_field("SenderIP",new IPAddress(3,16,47));
	/* Target MAC number */
	define_field("TrgMAC1",new NumericField(4,16,23));
	define_field("TrgMAC2",new NumericField(4,24,31));
	define_field("TrgMAC3",new NumericField(5,0,7));
	define_field("TrgMAC4",new NumericField(5,8,15));
	define_field("TrgMAC5",new NumericField(5,16,23));
	define_field("TrgMAC6",new NumericField(5,24,31));
	define_field("TargetIP",new IPAddress(6,0,31));
	/* Type */
}

void ARP::Craft () {
	TargetMAC = TrgMacFieldsToString();
	SenderMAC = SndMacFieldsToString();
}

void ARP::ReDefineActiveFields(){
	TargetMAC = TrgMacFieldsToString();
	SenderMAC = SndMacFieldsToString();
}

void ARP::LibnetBuild(libnet_t *l) {

	int r; /* Generic size */

	/* Put addresses on correct format */
	u_int8_t* sha = libnet_hex_aton(SenderMAC.c_str(),&r); /* Sender's hardware address */
	in_addr_t spa = inet_addr(GetSenderIP().c_str());                 /* Sender's protocol address */
	u_int8_t* tha = libnet_hex_aton(TargetMAC.c_str(),&r); /* Target's hardware address */
	in_addr_t tpa = inet_addr(GetTargetIP().c_str());                 /* Target's protocol address */

	/* Get the payload */
	size_t payload_size = GetPayloadSize();
	byte* payload;
	if (payload_size) {
		payload = new byte[payload_size];
		GetPayload(payload);
	} else
		payload = 0;

	/* Now write the data into de libnet context */
	int arp = libnet_build_arp (  GetHardwareType(),
								  GetProtocolType(),
								  GetHardwareLength(),
								  GetProtocolLength(),
								  GetOperation(),
								  sha,
								  (uint8_t *)& spa,
								  tha,
								  (uint8_t *)& tpa,
								  payload,
								  payload_size,
								  l,
								  0
							    );

	/* In case of error */
	if (arp == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "ARP::LibnetBuild()",
		             "Unable to build ARP header: " + string(libnet_geterror (l)));
		exit (1);
	}

	free(sha); free(tha);
	if(payload)
		delete [] payload;
}

std::string ARP::MatchFilter() const {
	/* Get IP Address of sender */
	string target_ip = GetTargetIP();
	word ip_number = ntohl(inet_addr(target_ip.c_str()));
	char* str_ip_number = new char[11];
	sprintf(str_ip_number,"%u",ip_number);
	str_ip_number[10] = 0;
	if (GetOperation() == ARP::Request) {
		string str = string(str_ip_number);
		delete [] str_ip_number;
		return "(arp[7]=2 and arp[14:4] == " + str + ")";
	} else {
		delete [] str_ip_number;
		return " ";
	}

}

void ARP::Print() const {
	cout << "< ";
	cout << name << " (" << dec << GetSize() << " bytes) " << ":: ";

	cout << "HardwareType = " << hex << GetHardwareType() << " ; ";
	cout << "ProtocolType = " << hex << GetProtocolType() << " ; ";
	cout << "HardwareLength = " << GetHardwareLength() << " ; ";
	cout << "ProtocolLength = " << GetProtocolLength() << " ; ";
	cout << "Operation = " << GetOperation() << " ; ";
	cout << "SenderMAC = " << GetSenderMAC() << " ; ";
	cout << "SenderIP = " << GetSenderIP() << " ; ";
	cout << "TargetMAC = " << GetTargetMAC() << " ; ";
	cout << "TargetIP = " << GetTargetIP() << " ; ";

	cout << "Payload = ";
	LayerPayload.Print();

	cout << ">" << endl;
}
