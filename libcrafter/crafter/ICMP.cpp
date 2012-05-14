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


#include "ICMP.h"
#include "IP.h"
#include "Crafter.h"
#include "CrafterUtils.h"

using namespace Crafter;
using namespace std;

ICMP::ICMP() {
		/* Allocate 2 words */
		allocate_words(2);
		/* Name of the protocol */
		SetName("ICMP");
		/* Set protocol NUmber */
		SetprotoID(0x01);

		/* This header support field overlapping */
		overlap_flag = 1;

		/* Creates field information for the layer */
		DefineProtocol();

		/* Always set default values for fields in a layer */
		SetType(8);
		SetCode(0);
		SetCheckSum(0);
		SetRestOfHeader(0);

		/* Always call this, reset all fields */
		ResetFields();
}

void ICMP::DefineProtocol() {
	/* Fields of the IP layer */
	define_field("Type",new NumericField(0,0,7));
	define_field("Code",new NumericField(0,8,15));
	define_field("CheckSum",new HexField(0,16,31));
	define_field("RestOfHeader",new NumericField(1,0,31));

	/* Ping header */
	define_field("Identifier", new HexField(1,0,15));
	define_field("SequenceNumber", new HexField(1,16,31));

	/* Pointer in Parameter Problem Message */
	define_field("Pointer", new NumericField(1,0,7));

	/* Internet Address on Redirect Message */
	define_field("Gateway", new IPAddress(1,0,31));

	/* Destination Unreachable, Time Exceeded and Parameter Problem (RFC4884) */
	define_field("Length", new NumericField(1, 8, 15));
}

/* Redefine active fields in function of the type of message */
void ICMP::ReDefineActiveFields() {

	/* Get the type of message and redefine fields */
	switch(GetType()) {

	case EchoReply:
		RedefineField("Identifier");
		RedefineField("SequenceNumber");
		break;

	case DestinationUnreachable:
                RedefineField("Length");
		break;

	case SourceQuench:
		break;

	case EchoRedirect:
		RedefineField("IPAddress");
		break;

	case EchoRequest:
		RedefineField("Identifier");
		RedefineField("SequenceNumber");
		break;

	case TimeExceeded:
        RedefineField("Length");
		break;

	case ParameterProblem:
		RedefineField("Pointer");
        RedefineField("Length");
		break;

	case TimeStampRequest:
		RedefineField("Identifier");
		RedefineField("SequenceNumber");
		break;

	case TimeStampReply:
		RedefineField("Identifier");
		RedefineField("SequenceNumber");
		break;

	case InformationRequest:
		RedefineField("Identifier");
		RedefineField("SequenceNumber");
		break;

	case InformationReply:
		RedefineField("Identifier");
		RedefineField("SequenceNumber");
		break;

	case AddressMaskRequest:
		RedefineField("Identifier");
		RedefineField("SequenceNumber");
		break;

	case AddressMaskReply:
		RedefineField("Identifier");
		RedefineField("SequenceNumber");
		break;

	default:
		break;
	}
}


void ICMP::LibnetBuild(libnet_t *l) {

	/* Get the payload */
	size_t payload_size = GetPayloadSize();
	byte* payload;
	if (payload_size) {
		payload = new byte[payload_size];
		GetPayload(payload);
	} else
		payload = 0;

	int icmp;

	in_addr_t gateway;

	/* Get the type of message and create packet */
	switch(GetType()) {

	case DestinationUnreachable:

		/* Now write the ICMP header into de libnet context */
		icmp = libnet_build_icmpv4_echo ( GetType(),
										  GetCode(),
										  GetCheckSum(),
										  GetLength(),
										  0,
										  payload,
										  payload_size,
										  l,
										  0
										);

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;

	case TimeExceeded:

		/* Now write the ICMP header into de libnet context */
		icmp = libnet_build_icmpv4_echo ( GetType(),
										  GetCode(),
										  GetCheckSum(),
										  GetLength(),
										  0,
										  payload,
										  payload_size,
										  l,
										  0
										);

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;

	case ParameterProblem:

		/* Now write the ICMP header into de libnet context */
		icmp = libnet_build_icmpv4_echo      ( GetType(),
										       GetCode(),
										       GetCheckSum(),
										       htons(GetPointer()) | GetLength(),
										       0,
										       payload,
										       payload_size,
										       l,
										       0
										      );

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;

	case SourceQuench:

		/* Now write the ICMP header into de libnet context */
		icmp = libnet_build_icmpv4_echo      ( GetType(),
										       GetCode(),
										       GetCheckSum(),
										       0,
										       0,
										       payload,
										       payload_size,
										       l,
										       0
										      );

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;

	case EchoRedirect:

		gateway = inet_addr(GetGateway().c_str());           /* Source protocol address */
		/* Now write the ICMP header into de libnet context */
		icmp = libnet_build_icmpv4_redirect  ( GetType(),
										       GetCode(),
										       GetCheckSum(),
										       gateway,
										       payload,
										       payload_size,
										       l,
										       0
										      );

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;

	case EchoReply:
		/* Now write the data into de libnet context */
		icmp = libnet_build_icmpv4_echo ( GetType(),
										  GetCode(),
										  GetCheckSum(),
										  GetIdentifier(),
										  GetSequenceNumber(),
										  payload,
										  payload_size,
										  l,
										  0
										);

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;

	case EchoRequest:

		/* Now write the data into de libnet context */
		icmp = libnet_build_icmpv4_echo ( GetType(),
										  GetCode(),
										  GetCheckSum(),
										  GetIdentifier(),
										  GetSequenceNumber(),
										  payload,
										  payload_size,
										  l,
										  0
										);

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;

	case InformationReply:
		/* Now write the data into de libnet context */
		icmp = libnet_build_icmpv4_echo ( GetType(),
										  GetCode(),
										  GetCheckSum(),
										  GetIdentifier(),
										  GetSequenceNumber(),
										  payload,
										  payload_size,
										  l,
										  0
										);

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;

	case InformationRequest:

		/* Now write the data into de libnet context */
		icmp = libnet_build_icmpv4_echo ( GetType(),
										  GetCode(),
										  GetCheckSum(),
										  GetIdentifier(),
										  GetSequenceNumber(),
										  payload,
										  payload_size,
										  l,
										  0
										);

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;

	default:
		/* Now write the data into de libnet context */
		icmp = libnet_build_icmpv4_echo ( GetType(),
										  GetCode(),
										  GetCheckSum(),
										  0,
										  0,
										  payload,
										  payload_size,
										  l,
										  0
										);

		/* In case of error */
		if (icmp == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "ICMP::LibnetBuild()",
			             "Unable to build ICMP header: " + string(libnet_geterror (l)));
			exit (1);
		}

		break;
	}

	if(payload)
		delete [] payload;

}

std::string ICMP::MatchFilter() const {
	short_word type = GetType();

	if ( type == EchoRequest || type == TimeStampRequest || type == InformationRequest || type == AddressMaskRequest) {
		short_word ident = GetIdentifier();
		char* str_ident = new char[6];
		sprintf(str_ident,"%d",ident);
		str_ident[5] = 0;
		string ret_string = "( icmp and icmp[4:2] == " + string(str_ident) + ") ";
		delete [] str_ident;
		return ret_string;
	} else
		return "";
}

/* Copy crafted packet to buffer_data */
void ICMP::Craft () {
	/* Calculates the ICMP original payload length (RFC4884) */
	word type = GetType();
	if (type == DestinationUnreachable ||
		type == TimeExceeded ||
		type == ParameterProblem) {
		word length = 0;
		Layer* layer = GetTopLayer();
		while (layer && layer->GetName() != "ICMPExtension") {
			length += layer->GetSize();
			/* Trick to make every sibling class a friend :) */
			layer = ((ICMP*) layer)->GetTopLayer();
		}
		SetLength(length / 4);
	}

	if (!IsFieldSet("CheckSum") || (GetCheckSum() == 0)) {

		/* Total size */
		size_t total_size = GetRemainingSize();
		if ( (total_size%2) != 0 ) total_size++;

		byte* buff_data = new byte[total_size];

		buff_data[total_size - 1] = 0x00;

		/* Compute the 16 bit checksum */
		SetCheckSum(0);

		GetData(buff_data);
		short_word checksum = CheckSum((unsigned short *)buff_data,total_size/2);
		SetCheckSum(ntohs(checksum));
		ResetField("CheckSum");

		delete [] buff_data;

	}

}

ICMP::~ICMP() { /* */ }
