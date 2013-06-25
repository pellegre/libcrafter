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

using namespace Crafter;
using namespace std;

IPv6::IPv6() {

    allocate_bytes(40);
    SetName("IPv6");
    SetprotoID(0x86dd);
    DefineProtocol();

    SetVersion(6);
    SetTrafficClass(0);
    SetFlowLabel(0);
    SetPayloadLength(0);
    SetNextHeader(0x06);
    SetHopLimit(64);
    SetSourceIP("0000::0000");
    SetDestinationIP("0000::0000");

    ResetFields();

}

void IPv6::DefineProtocol() {
    Fields.push_back(new BitsField<4,0>("Version",0));
    Fields.push_back(new BitsField<8,4>("TrafficClass",0));
    Fields.push_back(new BitsField<20,12>("FlowLabel",0));
    Fields.push_back(new ShortField("PayloadLength",1,0));
    Fields.push_back(new ByteField("NextHeader",1,2));
    Fields.push_back(new ByteField("HopLimit",1,3));
    Fields.push_back(new IPv6Address("SourceIP",2,0));
    Fields.push_back(new IPv6Address("DestinationIP",6,0));
}

