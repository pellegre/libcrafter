/*
Copyright (c) 2012, Bruno Nery
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

#include "ICMPExtensionObject.h"

using namespace Crafter;
using namespace std;

/* Classes (ClassNum) */
const byte ICMPExtensionObject::MPLS = 1;

/* Types (CType) */
/* +++ MPLS +++ */
const byte ICMPExtensionObject::MPLSReserved = 0;
const byte ICMPExtensionObject::MPLSIncoming = 1;

void ICMPExtensionObject::ReDefineActiveFields() {
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

std::string ICMPExtensionObject::GetClassName() const {
    word classnum = GetClassNum();
    switch (classnum) {
    case MPLS: return "ICMPExtensionMPLS";
    default: return "";
    }
}
