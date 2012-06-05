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

#include "TCP.h"

using namespace Crafter;
using namespace std;

TCP::TCP() {

    allocate_bytes(20);
    SetName("TCP");
    SetprotoID(0x06);
    DefineProtocol();

    SetSrcPort(0);
    SetDstPort(80);
    SetSeqNumber(0);
    SetAckNumber(0);
    SetDataOffset(5);
    SetReserved(0);
    SetFlags(0);
    SetWindowsSize(5840);
    SetCheckSum(0);
    SetUrgPointer(0);

    ResetFields();

}

void TCP::DefineProtocol() {
    Fields.push_back(new ShortField("SrcPort",0,0));
    Fields.push_back(new ShortField("DstPort",0,2));
    Fields.push_back(new WordField("SeqNumber",1,0));
    Fields.push_back(new WordField("AckNumber",2,0));
    Fields.push_back(new BitsField<4,0>("DataOffset",3));
    Fields.push_back(new BitsField<4,4>("Reserved",3));
    Fields.push_back(new TCPFlags("Flags",3,1));
    Fields.push_back(new ShortField("WindowsSize",3,2));
    Fields.push_back(new XShortField("CheckSum",4,0));
    Fields.push_back(new ShortField("UrgPointer",4,2));
}

