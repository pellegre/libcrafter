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
#include "TCPOptionLayer.h"
#include "TCPOptionMaxSegSize.h"
#include "TCPOptionPad.h"
#include "TCPOptionTimestamp.h"
#include <netinet/tcp.h>

using namespace Crafter;

TCPOptionLayer* TCPOptionLayer::Build(int opt) {

	switch(opt) {

	case TCPOPT_EOL:
		return new TCPOptionPad;
		break;
	case TCPOPT_NOP:
		return new TCPOptionPad;
		break;
	case TCP_MAXSEG:
		return new TCPOptionMaxSegSize;
		break;
	case TCPOPT_TIMESTAMP:
		return new TCPOptionTimestamp;
		break;
	case TCPOPT_SACK_PERMITTED:
		return new TCPOptionSACKPermitted;
		break;
	case TCPOPT_SACK:
		return new TCPOptionSACK;
		break;
	}

	/* Generic Option Header */
	return new TCPOption;
}

void TCPOptionLayer::ParseLayerData(ParseInfo* info) {
	/* Update the information of the IP options */
	ExtraInfo* extra_info = reinterpret_cast<ExtraInfo*>(info->extra_info);
	if(!extra_info) {
		info->top = 1;
		return;
	}

	extra_info->optlen -= GetSize();
	if(extra_info->optlen > 0) {
		/* Get the option type */
		int opt = (info->raw_data + info->offset)[0];
		info->next_layer = Build(opt);
	}  else {
		info->next_layer = extra_info->next_layer;
		delete extra_info;
		extra_info = 0;
	}
}
