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

#include "NullLoopback.h"
#include "IP.h"
#include "IPv6.h"
#include "RawLayer.h"

const int BSD_AF_INET = 2;
const int BSD_AF_INET6_BSD = 24;     /* OpenBSD (and probably NetBSD), BSD/OS */
const int BSD_AF_INET6_FREEBSD = 28;
const int BSD_AF_INET6_DARWIN = 30;

using namespace Crafter;
using namespace std;

void NullLoopback::Craft() {
	/* Nothing to do */
}

void NullLoopback::ParseLayerData(ParseInfo* info) {
	word network_layer = GetFamily();
	word proto_id;
	/* Get next layer */
    switch (network_layer) {

    case BSD_AF_INET:
    	proto_id = IP::PROTO;
      break;

    case BSD_AF_INET6_BSD:
    case BSD_AF_INET6_FREEBSD:
    case BSD_AF_INET6_DARWIN:
    	proto_id = IPv6::PROTO;
      break;

    default:
    	/* Go figure... */
    	proto_id = RawLayer::PROTO;
      break;
    }
	info->next_layer = Protocol::AccessFactory()->GetLayerByID(proto_id);
}

