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

#include "DHCP.h"

using namespace Crafter;
using namespace std;

/* Some constant of the DHCP protocol */
const byte DHCP::Request = 0x1;
const byte DHCP::Reply = 0x2;

DHCP::DHCP() {

	allocate_bytes(240);
    SetName("DHCP");
    SetprotoID(0xfff4);
    DefineProtocol();

    SetOperationCode(0x00);
    SetHardwareType(0x01);
    SetHardwareLength(6);
    SetHopCount(0);
    SetTransactionID(0x00);
    SetNumberOfSeconds(0);
    SetFlags(0x8000);
    SetClientIP("0.0.0.0");
    SetYourIP("0.0.0.0");
    SetServerIP("0.0.0.0");
    SetGatewayIP("0.0.0.0");
    SetClientMAC("ff:ff:ff:ff:ff:ff");
    SetServerHostName("");
    SetBootFile("");

    ResetFields();

}

void DHCP::DefineProtocol() {
    Fields.push_back(new XByteField("OperationCode",0,0));
    Fields.push_back(new XByteField("HardwareType",0,1));
    Fields.push_back(new ByteField("HardwareLength",0,2));
    Fields.push_back(new ByteField("HopCount",0,3));
    Fields.push_back(new XWordField("TransactionID",1,0));
    Fields.push_back(new ShortField("NumberOfSeconds",2,0));
    Fields.push_back(new XShortField("Flags",2,2));
    Fields.push_back(new IPAddress("ClientIP",3,0));
    Fields.push_back(new IPAddress("YourIP",4,0));
    Fields.push_back(new IPAddress("ServerIP",5,0));
    Fields.push_back(new IPAddress("GatewayIP",6,0));
    Fields.push_back(new MACAddress("ClientMAC",7,0));
    Fields.push_back(new BytesField<10>("ZeroPadding",8,2));
    Fields.push_back(new StringField<64>("ServerHostName",11,0));
    Fields.push_back(new StringField<128>("BootFile",27,0));
}

