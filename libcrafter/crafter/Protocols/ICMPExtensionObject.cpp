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

#include "ICMPExtensionObject.h"

using namespace Crafter;
using namespace std;

ICMPExtensionObject::ICMPExtensionObject() {
    allocate_words(1);
    SetName("ICMPExtensionObject");
    SetprotoID(0xFF);
    DefineProtocol();
    SetLength(0);
    SetClassNum(0);
    SetCType(0);
    ResetFields();
}

void ICMPExtensionObject::DefineProtocol() {
    define_field("Length", new NumericField(0, 0, 15));
    define_field("ClassNum", new NumericField(0, 16, 23));
    define_field("CType", new NumericField(0, 24, 31));
}

void ICMPExtensionObject::ReDefineActiveFields() {
    /* empty */
}

void ICMPExtensionObject::LibnetBuild(libnet_t *l) {
	/* Now write the data into the libnet context */
	int pay = libnet_build_data	( raw_data,
								  GetSize(),
								  l,
								  0
							    );

	/* In case of error */
	if (pay == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "ICMPExtensionObject::LibnetBuild()",
		             "Unable to build ICMPExtensionObject header: " + string(libnet_geterror (l)));
		exit (1);
	}
}

std::string ICMPExtensionObject::MatchFilter() const {
    return "";
}

void ICMPExtensionObject::Craft() {
    SetPayload(NULL, 0);


    Layer* layer = GetTopLayer();

    /* Set the extension object type/code */
    if (layer) {
        if (layer->GetName() == "ICMPExtensionMPLS") {
            SetClassNum(MPLS);
            SetCType(MPLSIncoming);
        } else {
            SetClassNum(0);
            SetCType(0);
        }
    }

    /* Set the extension object length */
    word length = 0;
    while (layer && layer->GetName() != "ICMPExtensionObject") {
        length += layer->GetSize();
        /* Trick to make every sibling class a friend :) */
        layer = ((ICMPExtensionObject*) layer)->GetTopLayer();
    }
    SetLength(GetSize() + length);
}

ICMPExtensionObject::~ICMPExtensionObject() {
    /* empty */
}
