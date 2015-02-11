/*
Copyright (c) 2015, Olivier Tilmans
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
DISCLAIMED. IN NO EVENT SHALL OLIVIER TILMANS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "IPv6SegmentRoutingHeader.h"

using namespace Crafter;
using namespace std;

IPv6SegmentRoutingHeader::IPv6SegmentRoutingHeader()
    : IPv6RoutingHeader(8, "IPv6SegmentRoutingHeader", 0x2b04, false) {
    DefineProtocol();
    SetDefaultValues();
    ResetFields();
}

void IPv6SegmentRoutingHeader::DefineProtocol() {
    Fields.push_back(new ByteField("FirstSegment",1,0));
    Fields.push_back(new BitFlag<8>("CFlag",1,"Cleanup","Keep"));
    Fields.push_back(new BitFlag<9>("PFlag",1,"Protected","NoFRR"));
    Fields.push_back(new BitsField<2,10>("Reserved",1));
    Fields.push_back(new BitsField<3,12>("PolicyFlag1",1));
    Fields.push_back(new BitsField<3,15>("PolicyFlag2",1));
    Fields.push_back(new BitsField<3,18>("PolicyFlag3",1));
    Fields.push_back(new BitsField<3,21>("PolicyFlag4",1));
    Fields.push_back(new ByteField("HMACKeyID",1,3));
}

void IPv6SegmentRoutingHeader::SetDefaultValues() {
    SetRoutingType(4);
    SetFirstSegment(0);
    SetCFlag(0);
    SetPFlag(0);
    SetReserved(0);
    for (size_t i = 0; i < policy_list_t::GetSize(); ++i)
        SetPolicyFlag(i, 0);
    SetHMACKeyID(0);
}

