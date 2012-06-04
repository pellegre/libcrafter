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
#include "IP.h"

using namespace Crafter;
using namespace std;

/* Pseudo header for UDP checksum */
struct psd_udp {
	struct in_addr src;
	struct in_addr dst;
	byte pad;
	byte proto;
	short_word udp_len;
};

/* Setup pseudo header and return the number of bytes copied */
static void setup_psd (word src, word dst, byte* buffer, size_t udp_size) {
	struct psd_udp buf;
	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_UDP;
	buf.udp_len = htons(udp_size);
	memcpy(buffer,(const byte *)&buf,sizeof(buf));
}

void UDP::ReDefineActiveFields() {

}

void UDP::Craft() {
	/* Get the layer on the bottom of this one, and verify that is an IP layer */
	IP* ip_layer = 0;
	/* Bottom layer name */
	Layer* bottom_ptr = GetBottomLayer();
	short_word bottom_layer = 0;
	if(bottom_ptr)  bottom_layer = bottom_ptr->GetID();

	/* Checksum of UDP packet */
	short_word checksum;

	size_t tot_length = GetRemainingSize();

	/* Set the Length of the UDP packet */
	if (!IsFieldSet(FieldLength)) {
		SetLength(tot_length);
		ResetField(FieldLength);
	}

	if (!IsFieldSet(FieldCheckSum)) {
		/* Set the checksum to zero */
		SetCheckSum(0x0);

		if(bottom_layer == 0x0800) {
			/* It's OK */
			ip_layer = dynamic_cast<IP*>(bottom_ptr);

			size_t data_length = sizeof(psd_udp) + tot_length;

			if(data_length%2 != 0) data_length++;

			vector<byte> raw_buffer(data_length,0);

			/* Setup the pseudo header */
			setup_psd(inet_addr(ip_layer->GetSourceIP().c_str()),
					  inet_addr(ip_layer->GetDestinationIP().c_str()),
					  &raw_buffer[0],tot_length);

			/* Setup the rest of the UDP datagram */
			GetData(&raw_buffer[sizeof(psd_udp)]);

			checksum = CheckSum((unsigned short *)&raw_buffer[0],raw_buffer.size()/2);

		} else {
			PrintMessage(Crafter::PrintCodes::PrintWarning,
					     "UDP::Craft()",
				         "Bottom Layer of UDP packet is not IP. Cannot calculate UDP checksum.");
			checksum = 0;
		}

		/* Set the checksum to zero */
		SetCheckSum(ntohs(checksum));
		ResetField(FieldCheckSum);
	}
}

string UDP::MatchFilter() const {
	char src_port[6];
	char dst_port[6];
	sprintf(src_port,"%d", GetSrcPort());
	sprintf(dst_port,"%d", GetDstPort());
	std::string ret_str = "udp and dst port " + std::string(src_port) + " and src port " + std::string(dst_port);
	return ret_str;
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

