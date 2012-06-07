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

#include "SLL.h"

using namespace Crafter;
using namespace std;

SLL::SLL() {

    allocate_bytes(16);
    SetName("SLL");
    SetprotoID(0xfff0);
    DefineProtocol();

    SetPackeType(0);
    SetAddressType(1);
    SetAddressLength(6);
    SetSourceAddress("00:00:00:00:00:00");
    SetProtocol(0x0800);

    ResetFields();

}

void SLL::DefineProtocol() {
    Fields.push_back(new ShortField("PackeType",0,0));
    Fields.push_back(new ShortField("AddressType",0,2));
    Fields.push_back(new ShortField("AddressLength",1,0));
    Fields.push_back(new MACAddress("SourceAddress",1,2));
    Fields.push_back(new BytesField<2>("Pad",3,0));
    Fields.push_back(new XShortField("Protocol",3,2));
}

