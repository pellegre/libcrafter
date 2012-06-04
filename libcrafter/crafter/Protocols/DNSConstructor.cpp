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

#include "DNS.h"

using namespace Crafter;
using namespace std;

DNS::DNS() {

    allocate_bytes(12);
    SetName("DNS");
    SetprotoID(0xfff3);
    DefineProtocol();

    Fields.SetOverlap(1);

    SetIdentification(0);
    SetQRFlag(0);
    SetOpCode(0);
    SetAAFlag(0);
    SetTCFlag(0);
    SetRDFlag(0);
    SetRAFlag(0);
    SetZFlag(0);
    SetADFlag(0);
    SetCDFlag(0);
    SetRCode(0);
    SetTotalQuestions(0);
    SetTotalAnswer(0);
    SetTotalAuthority(0);
    SetTotalAdditional(0);

    ResetFields();

}

void DNS::DefineProtocol() {
    Fields.push_back(new XShortField("Identification",0,0));
    Fields.push_back(new BitFlag<16>("QRFlag",0,"Response","Query"));
    Fields.push_back(new BitsField<4,17>("OpCode",0));
    Fields.push_back(new BitsField<1,21>("AAFlag",0));
    Fields.push_back(new BitsField<1,22>("TCFlag",0));
    Fields.push_back(new BitsField<1,23>("RDFlag",0));
    Fields.push_back(new BitsField<1,24>("RAFlag",0));
    Fields.push_back(new BitsField<1,25>("ZFlag",0));
    Fields.push_back(new BitsField<1,26>("ADFlag",0));
    Fields.push_back(new BitsField<1,27>("CDFlag",0));
    Fields.push_back(new BitsField<4,28>("RCode",0));
    Fields.push_back(new ShortField("TotalQuestions",1,0));
    Fields.push_back(new ShortField("TotalAnswer",1,2));
    Fields.push_back(new ShortField("TotalAuthority",2,0));
    Fields.push_back(new ShortField("TotalAdditional",2,2));
    Fields.push_back(new ShortField("TotalQuestions",1,0));
}
