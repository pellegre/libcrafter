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

#include "ARP.h"

using namespace Crafter;
using namespace std;

ARP::ARP() {

    allocate_bytes(28);
    SetName("ARP");
    SetprotoID(0x0806);
    DefineProtocol();

    SetHardwareType(0x01);
    SetProtocolType(0x0800);
    SetHardwareLength(0x06);
    SetProtocolLength(0x04);
    SetOperation(0x01);
    SetSenderMAC("00:00:00:00:00:00");
    SetSenderIP("127.0.0.1");
    SetTargetMAC("00:00:00:00:00:00");
    SetTargetIP("127.0.0.1");

    ResetFields();

}

void ARP::DefineProtocol() {
    Fields.push_back(new XShortField("HardwareType",0,0));
    Fields.push_back(new XShortField("ProtocolType",0,2));
    Fields.push_back(new ByteField("HardwareLength",1,0));
    Fields.push_back(new ByteField("ProtocolLength",1,1));
    Fields.push_back(new ShortField("Operation",1,2));
    Fields.push_back(new MACAddress("SenderMAC",2,0));
    Fields.push_back(new IPAddress("SenderIP",3,2));
    Fields.push_back(new MACAddress("TargetMAC",4,2));
    Fields.push_back(new IPAddress("TargetIP",6,0));
}

