/*
Copyright (c) 2015, Olivier Tilmans
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
DISCLAIMED. IN NO EVENT SHALL OLIVIER TILMANS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "IPv6RoutingHeader.h"
#include "IPv6SegmentRoutingHeader.h"
#include "IPv6MobileRoutingHeader.h"
#include "IPv6.h"


using namespace Crafter;
using namespace std;


IPv6RoutingHeader* IPv6RoutingHeader::Build(int type) {
    switch(type) {
        case 0: /* Routing Header Type 0 -- DEPRECATED */
        case 1: /* Nimrod -- DEPRECATED 2009-05-06 */
            return new IPv6RoutingHeader;
        case 2: /* IPv6 mobility -- rfc6275 */
            return new IPv6MobileRoutingHeader;
        case 3: /* RPL -- rfc6554 */
            return new IPv6RoutingHeader;
        case 4: /* Segment Routing -- draft-previdi-6man-segment-routing-header */
            return new IPv6SegmentRoutingHeader;
        case 253: /* IETF Experimental values -- rfc4727 */
        case 254: /* IETF Experimental values -- rfc4727 */
            return new IPv6RoutingHeader;
    }
    /* Defaulting to an opaque layer */
    return new IPv6RoutingHeader;
}

size_t IPv6RoutingHeader::GetRoutingPayloadSize() const {
    /* Everything in type data + the required _unused_ 4 bytes of the header
     * that will change depending on the ehader type */
    return GetHeaderExtLen() * 8 + 4;
}

void IPv6RoutingHeader::FillRoutingPayload(byte *payload) const {
    /* Nothing to put in the payload, just nullify it */
    memset(payload, 0, GetRoutingPayloadSize());
}

void IPv6RoutingHeader::Craft() {
    /* Skipping HdrExtLen and SegmentsLeft because these have sane default
     * for an opaque header.
     */
    if (!IsFieldSet(FieldRoutingType)) {
        SetRoutingType(protoID & 0xFF);
        ResetField(FieldRoutingType);
    }

    if (TopLayer) {
        if (!IsFieldSet(FieldNextHeader)) {
            SetNextHeader(IPv6::GetIPv6NextHeader(TopLayer->GetID()));
            ResetField(FieldNextHeader);
        }
        else {
            PrintMessage(Crafter::PrintCodes::PrintWarning,
                "IPv6RoutingHeader::Craft()", "No transport layer protocol.");
        }
    }

    size_t payload_size = GetRoutingPayloadSize();
    if (payload_size) {
        byte* raw_payload = new byte[payload_size];
        FillRoutingPayload(raw_payload);

        SetPayload(raw_payload, payload_size);
    }
}

void IPv6RoutingHeader::ParseLayerData(ParseInfo *info) {
    Craft();
    /* We only need to worry about the payload, as ParseData will already have
     * incremented the offset by the size of the fixed header. */
    info->offset += GetRoutingPayloadSize();
    info->next_layer = IPv6::GetNextLayer(info, GetNextHeader());
}

