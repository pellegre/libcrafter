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

#include "IP.h"

using namespace Crafter;
using namespace std;

IP::IP() {

    allocate_bytes(20);
    SetName("IP");
    SetprotoID(0x0800);
    DefineProtocol();

    SetVersion(4);
    SetHeaderLength(5);
    SetDiffServicesCP(0);
    SetExpCongestionNot(0);
    SetTotalLength(0);
    SetIdentification(0);
#ifdef __APPLE__
    SetFlags(0);
#else
    SetFlags(0x02);
#endif
    SetFragmentOffset(0);
    SetTTL(64);
    SetProtocol(0x06);
    SetCheckSum(0);
    SetSourceIP("0.0.0.0");
    SetDestinationIP("0.0.0.0");

    ResetFields();

}

void IP::DefineProtocol() {
    Fields.push_back(new BitsField<4,0>("Version",0));
    Fields.push_back(new BitsField<4,4>("HeaderLength",0));
    Fields.push_back(new BitsField<6,8>("DiffServicesCP",0));
    Fields.push_back(new BitsField<2,14>("ExpCongestionNot",0));
#ifdef __APPLE__
	/* see http://cseweb.ucsd.edu/~braghava/notes/freebsd-sockets.txt */
    Fields.push_back(new ShortHostNetField("TotalLength",0,2));
#else
    Fields.push_back(new ShortField("TotalLength",0,2));
#endif
    Fields.push_back(new XShortField("Identification",1,0));
    Fields.push_back(new BitsField<3,16>("Flags",1));
    Fields.push_back(new BitsField<13,19>("FragmentOffset",1));
    Fields.push_back(new ByteField("TTL",2,0));
    Fields.push_back(new XByteField("Protocol",2,1));
    Fields.push_back(new XShortField("CheckSum",2,2));
    Fields.push_back(new IPAddress("SourceIP",3,0));
    Fields.push_back(new IPAddress("DestinationIP",4,0));
}

