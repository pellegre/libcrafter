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


#include "TCP.h"
#include <netinet/tcp.h>

using namespace std;
using namespace Crafter;

/* Pseudo header for TCP checksum */
struct psd_tcp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short tcp_len;
};

/* Setup pseudo header and return the number of bytes copied */
static void setup_psd (word src, word dst, byte* buffer, size_t tcp_size) {
	struct psd_tcp buf;
	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_TCP;
	buf.tcp_len = htons(tcp_size);
	memcpy(buffer,(const byte *)&buf,sizeof(buf));
}

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
	short_word bottom_layer = 0;
	if(bottom_ptr)  bottom_layer = bottom_ptr->GetID();

	/* Checksum of UDP packet */
	short_word checksum;

	/* Check the options and update header length */
	size_t option_length = (GetSize() - GetHeaderSize())/4;
	if (option_length)
		if (!IsFieldSet("OffRes")) {
			SetDataOffset(5 + option_length);
			ResetField("OffRes");
		}

	FieldInfo* ptr_check = GetFieldPtr("CheckSum");

	size_t tot_length = GetRemainingSize();

	if (!IsFieldSet(ptr_check)) {
		/* Set the checksum to zero */
		SetFieldValue<word>(ptr_check,0x0);

		if(bottom_layer == 0x0800) {
			/* It's OK */
			ip_layer = dynamic_cast<IP*>(bottom_ptr);

			size_t data_length = sizeof(psd_tcp) + tot_length;

			if(data_length%2 != 0) data_length++;

			vector<byte> raw_buffer(data_length,0);

			/* Setup the pseudo header */
			setup_psd(inet_addr(ip_layer->GetSourceIP().c_str()),
					  inet_addr(ip_layer->GetDestinationIP().c_str()),
					  &raw_buffer[0],tot_length);

			/* Setup the rest of the UDP datagram */
			GetData(&raw_buffer[sizeof(psd_tcp)]);

			checksum = CheckSum((unsigned short *)&raw_buffer[0],raw_buffer.size()/2);

		} else {
			PrintMessage(Crafter::PrintCodes::PrintWarning,
					     "TCP::Craft()",
				         "Bottom Layer of TCP packet is not IP. Cannot calculate TCP checksum.");
			checksum = 0;
		}

		/* Set the checksum to zero */
		SetFieldValue<word>(ptr_check,ntohs(checksum));
		ResetField(ptr_check);
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

