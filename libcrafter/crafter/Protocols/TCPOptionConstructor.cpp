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

#include "TCPOption.h"

using namespace Crafter;
using namespace std;

static TCPOptionPad SetOptionKind(byte value) {
	TCPOptionPad pad;
	pad.SetKind(value);
	return pad;
}

const TCPOptionPad TCPOption::NOP = SetOptionKind(0x01);
const TCPOptionPad TCPOption::EOL = SetOptionKind(0x00);

TCPOption::TCPOption() {

    allocate_bytes(2);
    SetName("TCPOption");
    SetprotoID(0x9000);
    DefineProtocol();

    SetKind(0);
    SetLength(2);

    ResetFields();
}

void TCPOption::DefineProtocol() {
    Fields.push_back(new ByteField("Kind",0,0));
    Fields.push_back(new ByteField("Length",0,1));
}

TCPOptionSACKPermitted::TCPOptionSACKPermitted() {

    SetName("TCPOptionSACKPermitted");
    SetprotoID(0x9004);

    SetKind(0x04);
    SetLength(2);

    ResetFields();
}

TCPOptionSACK::TCPOptionSACK() {

    SetName("TCPOptionSACK");
    SetprotoID(0x9005);

    SetKind(0x05);
    SetLength(2);

    ResetFields();
}

TCPOptionFastOpen::TCPOptionFastOpen() {

    SetName("TCPOptionFastOpen");
    SetprotoID(TCPOptionFastOpen::PROTO);

    SetKind(TCPOPT_TFO);
    SetLength(2);

    ResetFields();
}

TCPOptionEDO::TCPOptionEDO(byte length) : TCPOption() {
	SetName("TCPOptionEDO");
    SetprotoID(TCPOptionEDO::PROTO);

    SetKind(TCPOPT_EDO);
    SetLength(length);

    ResetFields();
}
