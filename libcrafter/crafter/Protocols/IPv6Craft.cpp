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

#include "IPv6.h"
#include "ICMPv6Layer.h"

using namespace Crafter;
using namespace std;

void IPv6::ReDefineActiveFields() {
}

void IPv6::Craft() {

	/* Get transport layer protocol */
	if(TopLayer) {

		/* First, put the total length on the header */
		if (!IsFieldSet(FieldPayloadLength)) {
			SetPayloadLength(( (IPv6*)TopLayer)->GetRemainingSize());
			ResetField(FieldPayloadLength);
		}

		if(!IsFieldSet(FieldNextHeader)) {
			short_word transport_layer = TopLayer->GetID();
			/* Set Protocol */
			if(transport_layer != 0xfff1) {
				if ((TopLayer->GetID() >> 8) == (ICMPv6Layer::PROTO >> 8))
					SetNextHeader((ICMPv6Layer::PROTO >> 8));
				else
					SetNextHeader(transport_layer);
			}
			else
				SetNextHeader(0x0);

			ResetField(FieldNextHeader);
		}
	}
	else {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "IPv6::Craft()","No Transport Layer Protocol associated with IPv6 Layer.");
	}

}

string IPv6::MatchFilter() const {
	return "ip6 and dst host " + GetSourceIP() + " and src host " + GetDestinationIP();
}

void IPv6::ParseLayerData(ParseInfo* info) {
	size_t total_length = this->GetPayloadLength() * 8;
	size_t total_data = info->total_size - info->offset;

	/* Detect ethernet padding */
	if(total_length && total_data > total_length) {
		info->total_size -= (total_data - total_length);
	}

	short_word network_layer = GetNextHeader();
	if(network_layer == (ICMPv6Layer::PROTO >> 8)) {
		/* Get ICMPv6 type */
		short_word icmpv6_layer = (info->raw_data + info->offset)[0];
		/* Construct next layer */
		info->next_layer = ICMPv6Layer::Build(icmpv6_layer);
	} else {
		info->next_layer = Protocol::AccessFactory()->GetLayerByID(network_layer);
	}
}
