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

#include "IP.h"
#include "RawLayer.h"
#include "IPOption.h"

using namespace std;
using namespace Crafter;

const size_t MAXOPT = 40;
const size_t IPHDRSIZE = 20;

void IP::ReDefineActiveFields() {
}

void IP::Craft() {

	size_t tot_length = GetRemainingSize();

	/* First, put the total length on the header */
	if (!IsFieldSet(FieldTotalLength)) {
		SetTotalLength(tot_length);
		ResetField(FieldTotalLength);
	}

	/* Array for the option data */
	byte ip_data[IPHDRSIZE + MAXOPT];
	memset(ip_data, 0, IPHDRSIZE + MAXOPT);

	size_t option_length = 0;

	/* Check the options and update header length */
	if (!IsFieldSet(FieldHeaderLength)) {
		Layer* top_layer = GetTopLayer();
		if(top_layer) {
			while( top_layer && ((top_layer->GetID() >> 8) == (IPOption::PROTO >> 8))) {
				size_t last_opt_length = option_length;
				/* Update option length */
				option_length += top_layer->GetSize();
				/* Get the option data */
				if(option_length <= MAXOPT) top_layer->GetRawData(ip_data + IPHDRSIZE + last_opt_length);
				/* Go to next layer */
				top_layer = ((IP *)top_layer)->GetTopLayer();
			}
		}

		if(option_length%4 != 0)
			PrintMessage(Crafter::PrintCodes::PrintWarning,
					     "IP::Craft()",
				         "Option size is not padded to a multiple of 4 bytes.");

		SetHeaderLength(5 + option_length/4);
		ResetField(FieldHeaderLength);

		/* Get transport layer protocol */
		if(top_layer) {
			if(!IsFieldSet(FieldProtocol)) {
				short_word transport_layer = top_layer->GetID();
				/* Set Protocol */
				if(transport_layer != RawLayer::PROTO)
					SetProtocol(transport_layer);
				else
					SetProtocol(0x0);

				ResetField(FieldProtocol);
			}
		}
		else {
			PrintMessage(Crafter::PrintCodes::PrintWarning,
					     "IP::Craft()","No Transport Layer Protocol associated with IP Layer.");
		}
	}

	size_t ip_length = option_length + 20;
	if(ip_length > (MAXOPT + IPHDRSIZE) ) ip_length = MAXOPT + IPHDRSIZE;

	if (!IsFieldSet(FieldCheckSum)) {
		/* Compute the 16 bit checksum */
		SetCheckSum(0);
		GetRawData(ip_data);
		/* Calculate the checksum */
		short_word checksum = CheckSum((unsigned short *)ip_data,ip_length/2);
		SetCheckSum(ntohs(checksum));
		ResetField(FieldCheckSum);
	}
}

string IP::MatchFilter() const {
	return "ip and dst host " + GetSourceIP() + " and src host " + GetDestinationIP();
}

void IP::ParseLayerData(ParseInfo* info) {
	size_t total_length = this->GetTotalLength() - this->GetSize();
	size_t total_data = info->total_size - info->offset;

	/* Detect ethernet padding */
	if(total_data > total_length) {
		info->total_size -= (total_data - total_length);
	}

	/* Verify if there are options on the IP header */
	size_t IP_word_size = GetHeaderLength();
	size_t IP_opt_size = 0;

	if(IP_word_size > 5) IP_opt_size = 4 * (IP_word_size - 5);

	short_word network_layer = GetProtocol();

	/* We have a valid set of options */
	if (IP_opt_size > 0) {
		/* Extra information for IP options */
		IPOptionLayer::ExtraInfo* extra_info = new IPOptionLayer::ExtraInfo;
		extra_info->optlen = IP_opt_size;
		extra_info->next_layer = Protocol::AccessFactory()->GetLayerByID(network_layer);

		/* Information for the decoder */
		int opt = (info->raw_data + info->offset)[0];
		info->next_layer = IPOptionLayer::Build(opt);
		info->extra_info = reinterpret_cast<void*>(extra_info);
	} else {
		info->next_layer = Protocol::AccessFactory()->GetLayerByID(network_layer);
	}
}
