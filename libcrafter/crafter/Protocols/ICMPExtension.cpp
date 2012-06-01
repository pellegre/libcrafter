/*
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

#include "ICMPExtension.h"

using namespace Crafter;
using namespace std;

ICMPExtension::ICMPExtension() {
    allocate_words(1);
    SetName("ICMPExtension");
    SetprotoID(0xFF);
    DefineProtocol();
    SetVersion(2);
    SetReserved(0);
    SetChecksum(0);
    ResetFields();
}

void ICMPExtension::DefineProtocol() {
    define_field("VerRes", new BitField<short_word,4,12>(0,0,15,"Version","Reserved"));
    define_field("Checksum", new HexField(0, 16, 31));
}

void ICMPExtension::ReDefineActiveFields() {
    /* empty */
}

void ICMPExtension::LibnetBuild(libnet_t *l) {
	/* Now write the data into de libnet context */
	int pay = libnet_build_data	( raw_data,
								  GetSize(),
								  l,
								  0
							    );

	/* In case of error */
	if (pay == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "ICMPExtension::LibnetBuild()",
		             "Unable to build ICMPExtension header: " + string(libnet_geterror (l)));
		exit (1);
	}
}

std::string ICMPExtension::MatchFilter() const {
    return "";
}

void ICMPExtension::Craft() {
    SetPayload(NULL, 0);

	if (!IsFieldSet("Checksum") || (GetChecksum() == 0)) {

		/* Total size */
		size_t total_size = GetRemainingSize();
		if ( (total_size%2) != 0 ) total_size++;

		byte* buff_data = new byte[total_size];

		buff_data[total_size - 1] = 0x00;

		/* Compute the 16 bit checksum */
		SetChecksum(0);

		GetData(buff_data);
		short_word checksum = CheckSum((unsigned short *)buff_data,total_size/2);
		SetChecksum(ntohs(checksum));
		ResetField("Checksum");

		delete [] buff_data;

	}}

ICMPExtension::~ICMPExtension() {
    /* empty */
}
