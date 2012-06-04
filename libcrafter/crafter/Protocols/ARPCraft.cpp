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

void ARP::ReDefineActiveFields() {
}

void ARP::Craft() {
}

string ARP::MatchFilter() const {
	/* Get IP Address of sender */
	string target_ip = GetTargetIP();
	word ip_number = ntohl(inet_addr(target_ip.c_str()));
	char str_ip_number[11];
	sprintf(str_ip_number,"%u",ip_number);
	str_ip_number[10] = 0;
	if (GetOperation() == ARP::Request) {
		string str = string(str_ip_number);
		return "(arp[7]=2 and arp[14:4] == " + str + ")";
	} else {
		return " ";
	}
}

void ARP::LibnetBuild(libnet_t *l) {

	int r; /* Generic size */

	/* Put addresses on correct format */
	u_int8_t* sha = libnet_hex_aton(GetSenderMAC().c_str(),&r); /* Sender's hardware address */
	in_addr_t spa = inet_addr(GetSenderIP().c_str());                 /* Sender's protocol address */
	u_int8_t* tha = libnet_hex_aton(GetTargetMAC().c_str(),&r); /* Target's hardware address */
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
								  (uint8_t *)payload,
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

