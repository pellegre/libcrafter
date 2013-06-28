/*
Copyright (c) 2013, Gregory Detal
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

#include "TCPOptionMPTCP.h"

using namespace Crafter;
using namespace std;

TCPOptionMPTCP::TCPOptionMPTCP() {

    allocate_bytes(2);
    SetName("TCPOptionMPTCP");
    SetprotoID(0x9006);
    DefineProtocol();

    SetKind(30);
    SetLength(2);
}

void TCPOptionMPTCP::DefineProtocol() {
    Fields.push_back(new ByteField("Kind",0,0));
    Fields.push_back(new ByteField("Length",0,1));
    Fields.push_back(new BitsField<4,16>("Subtype",0));
}

TCPOptionMPTCPCapable::TCPOptionMPTCPCapable() {
    allocate_bytes(12);
    SetName("TCPOptionMPTCPCapable");
    SetprotoID(0x9007);
    DefineProtocol();

    SetKind(30);
    SetLength(12);
    SetVersion(0);
    SetSubtype(0);
    SetCrypto(1);
}

void TCPOptionMPTCPCapable::DefineProtocol() {
    Fields.push_back(new BitsField<4,20>("Version",0));
    Fields.push_back(new BitFlag<24>("Checksum",0,"Checksum Enabled","Checksum Disabled"));
    Fields.push_back(new BitsField<6,25>("Flags",0));
    Fields.push_back(new BitFlag<31>("Crypto",0,"HMAC-SHA1","NO HMAC-SHA1"));
    Fields.push_back(new Int64Field("Sender's Key",1,0));
}

