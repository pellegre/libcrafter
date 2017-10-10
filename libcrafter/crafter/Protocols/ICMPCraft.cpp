/*
Copyright (c) 2012, Esteban Pellegrino

 + ICMP Extensions
Copyright (c) 2012, Bruno Nery

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
#include "ICMPLayer.h"

using namespace Crafter;
using namespace std;

/* ------- Messages types --------- */

/* +++ Other +++ */
const byte ICMP::SourceQuench = 4;
const byte ICMP::EchoRedirect = 5;

/* +++ Error messages +++ */
const byte ICMP::DestinationUnreachable = 3;
const byte ICMP::TimeExceeded = 11;
const byte ICMP::ParameterProblem = 12;

/* +++ Request and replies +++ */
const byte ICMP::EchoRequest = 8;
const byte ICMP::EchoReply = 0;

const byte ICMP::TimeStampRequest = 13;
const byte ICMP::TimeStampReply = 14;

const byte ICMP::InformationRequest = 15;
const byte ICMP::InformationReply = 16;

const byte ICMP::AddressMaskRequest = 17;
const byte ICMP::AddressMaskReply = 18;

byte ICMP::MapTypeNumber(short_word type) {
	/* Get the type of message in function of the base type */
	if(type == ICMPLayer::DestinationUnreachable)
		return ICMP::DestinationUnreachable;
	else if(type == ICMPLayer::TimeExceeded)
		return ICMP::TimeExceeded;
	else if(type == ICMPLayer::ParameterProblem)
		return ICMP::ParameterProblem;
	else if(type == ICMPLayer::EchoReply)
		return ICMP::EchoReply;
	else if(type == ICMPLayer::EchoRequest)
		return ICMP::EchoRequest;
	return type;
}


void ICMP::ReDefineActiveFields() {
	/* Get the type of message and redefine fields */
	switch(GetType()) {

	case EchoReply:
		RedefineField(FieldIdentifier);
		RedefineField(FieldSequenceNumber);
		break;

	case DestinationUnreachable:
        RedefineField(FieldLength);
        RedefineField(FieldMTUNextHop);
		break;

	case SourceQuench:
		break;

	case EchoRedirect:
		RedefineField(FieldGateway);
		break;

	case EchoRequest:
		RedefineField(FieldIdentifier);
		RedefineField(FieldSequenceNumber);
		break;

	case TimeExceeded:
        RedefineField(FieldLength);
		break;

	case ParameterProblem:
		RedefineField(FieldPointer);
        RedefineField(FieldLength);
		break;

	case TimeStampRequest:
		RedefineField(FieldIdentifier);
		RedefineField(FieldSequenceNumber);
		break;

	case TimeStampReply:
		RedefineField(FieldIdentifier);
		RedefineField(FieldSequenceNumber);
		break;

	case InformationRequest:
		RedefineField(FieldIdentifier);
		RedefineField(FieldSequenceNumber);
		break;

	case InformationReply:
		RedefineField(FieldIdentifier);
		RedefineField(FieldSequenceNumber);
		break;

	case AddressMaskRequest:
		RedefineField(FieldIdentifier);
		RedefineField(FieldSequenceNumber);
		break;

	case AddressMaskReply:
		RedefineField(FieldIdentifier);
		RedefineField(FieldSequenceNumber);
		break;

	default:
		break;
	}
}

void ICMP::Craft() {
	/* Calculates the ICMP original payload length (RFC4884) */
	word type = GetType();
	if ( (type == DestinationUnreachable || type == TimeExceeded ||
				type == ParameterProblem) && !IsFieldSet(FieldLength)) {
		word length = 0;
		Layer* layer = GetTopLayer();
		while (layer && layer->GetName() != "ICMPExtension") {
			length += layer->GetSize();
			/* Trick to make every sibling class a friend :) */
            layer = layer->GetTopLayer();
		}
		SetLength(length / 4);
		if (layer && layer->GetName() == "ICMPExtension" &&
				(length < 128 || length % 4))
			PrintMessage(PrintCodes::PrintWarning,
					"Missing padding bytes between ICMP "
					"payload and extensions! (see RFC4884)");
	}

	if (!IsFieldSet(FieldCheckSum)) {

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
		ResetField(FieldCheckSum);

		delete [] buff_data;

	}
}

string ICMP::MatchFilter() const {
	short_word type = GetType();

	if ( type == EchoRequest || type == TimeStampRequest ||
			type == InformationRequest || type == AddressMaskRequest) {
		short_word ident = GetIdentifier();
		char str_ident[6];
		sprintf(str_ident,"%d",ident);
		str_ident[5] = 0;
		string ret_string = "( icmp and icmp[4:2] == " + string(str_ident) + ") ";
		return ret_string;
	} else
		return " icmp ";
}

void ICMP::ParseLayerData(ParseInfo* info) {
    word icmp_type = GetType();

	/* Per RFC 4884, §5.5/5.4, specific ICMP types may have extensions,
	 * beside their "original datagram" field */
    if (icmp_type == ICMP::DestinationUnreachable ||
			icmp_type == ICMP::TimeExceeded ||
			icmp_type == ICMP::ParameterProblem)
		ICMPLayer::parseExtensionHeader(info, 4 * GetLength());
    else
		/* No more layers */
		info->top = 1;
}
