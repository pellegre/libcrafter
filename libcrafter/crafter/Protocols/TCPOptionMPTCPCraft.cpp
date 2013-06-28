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
#include "../Utils/BitHandling.h"

using namespace Crafter;
using namespace std;

void TCPOptionMPTCP::Craft() {
	SetLength(GetLength() + GetPayloadSize());
}

void TCPOptionMPTCPCapable::SetReceiverKey(const uint64_t& value) {
	word* data = new word[2];
	*((uint64_t *)data) = htonll(value);

	SetPayload((const byte*)data,sizeof(uint64_t)); 
}

uint64_t TCPOptionMPTCPCapable::GetReceiverKey() const {
	size_t payload_size = GetPayloadSize();
	if( payload_size > 0) {
		const byte* raw_data = GetPayload().GetRawPointer();
		return ntohll(*(const uint64_t *)(raw_data));
	}
	return 0;
}

TCPOptionLayer* TCPOptionMPTCP::Build(int subopt) {

	switch(subopt) {
	case 0:
		std::cout << "TCPOptionMPTCP::Build::TCPOptionMPTCPCapable" << std::endl;
		return new TCPOptionMPTCPCapable;
	}

	/* Generic Option Header */
	return new TCPOption;
}
