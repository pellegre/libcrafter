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

using namespace std;
using namespace Crafter;

void IP::ReDefineActiveFields() {
}

void IP::Craft() {
	size_t tot_length = GetRemainingSize();

	/* First, put the total length on the header */
	if (!IsFieldSet(FieldTotalLength)) {
		SetTotalLength(tot_length);
		ResetField(FieldTotalLength);
	}

	/* Get transport layer protocol */
	if(TopLayer) {
		if(!IsFieldSet(FieldProtocol)) {
			short_word transport_layer = TopLayer->GetID();
			/* Set Protocol */
			if(transport_layer != 0xfff1)
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

	/* Check the options and update header length */
	size_t option_length = (GetSize() - GetHeaderSize())/4;
	if (option_length)
	if (!IsFieldSet(FieldHeaderLength)) {
		SetHeaderLength(5 + option_length);
		ResetField(FieldHeaderLength);
	}

	if (!IsFieldSet(FieldCheckSum)) {
		/* Compute the 16 bit checksum */
		SetCheckSum(0);
		byte* buffer = new byte[GetSize()];
		GetRawData(buffer);
		/* Calculate the checksum */
		short_word checksum = CheckSum((unsigned short *)buffer,GetSize()/2);
		SetCheckSum(ntohs(checksum));
		delete [] buffer;
		ResetField(FieldCheckSum);
	}
}

string IP::MatchFilter() const {
	return "ip and dst host " + GetSourceIP() + " and src host " + GetDestinationIP();
}
