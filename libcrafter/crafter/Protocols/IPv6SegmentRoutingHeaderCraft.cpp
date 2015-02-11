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

#include "IPv6SegmentRoutingHeader.h"

using namespace Crafter;
using namespace std;


size_t IPv6SegmentRoutingHeader::GetRoutingPayloadSize() const {
    /* Check if we don't already know the header length */
    size_t s = GetHeaderExtLen() * 8;
    if (s)
        return s;

    /* Base payload size is sum of segments size */
    s = Segments.size() * SEGMENT_SIZE;

    /* Check if we have some policy addresses set */ 
    if (SRPolicy::IsSet(GetPolicyFlag1()))
        s += SRPolicy::SRPOLICY_SIZE;
    if (SRPolicy::IsSet(GetPolicyFlag2()))
        s += SRPolicy::SRPOLICY_SIZE;
    if (SRPolicy::IsSet(GetPolicyFlag3()))
        s += SRPolicy::SRPOLICY_SIZE;
    if (SRPolicy::IsSet(GetPolicyFlag4()))
        s += SRPolicy::SRPOLICY_SIZE;

    /* HMAC field present iff HMACKeyID set */
    if (GetHMACKeyID())
        s += HMAC_SIZE; 
    
    return s;
}

void IPv6SegmentRoutingHeader::FillRoutingPayload(byte *payload) const {
    /* Put all segments at the start */
    vector<segment_t>::const_iterator it;
    for (it = Segments.begin(); it != Segments.end(); ++it, payload += SEGMENT_SIZE)
        memcpy(payload, it->s, SEGMENT_SIZE);

    /* Then the policy list */
    if (SRPolicy::IsSet(GetPolicyFlag1())) {
        PolicyList[0].Write(payload);
        payload += SRPolicy::SRPOLICY_SIZE;
    }
    if (SRPolicy::IsSet(GetPolicyFlag2())) {
        PolicyList[1].Write(payload);
        payload += SRPolicy::SRPOLICY_SIZE;
    }
    if (SRPolicy::IsSet(GetPolicyFlag3())) {
        PolicyList[2].Write(payload);
        payload += SRPolicy::SRPOLICY_SIZE;
    }
    if (SRPolicy::IsSet(GetPolicyFlag4())) {
        PolicyList[3].Write(payload);
        payload += SRPolicy::SRPOLICY_SIZE;
    }

    /* Then the HMAC */
    if (GetHMACKeyID()) {
        memcpy(payload, HMAC, HMAC_SIZE);
        payload += HMAC_SIZE;
    }
}

void IPv6SegmentRoutingHeader::Craft() {
    /* By default, segment left will point to the segment on top of the stack,
     * thus the first one in the segment routed path */
    if (!IsFieldSet(FieldSegmentLeft)) {
        SetSegmentLeft(Segments.size() - 1);
        ResetField(FieldSegmentLeft);
    }

    /* Users normally shouldn't need to set it manually as it is defined as the
     * very first segment of the stack (thus the deepest one in the header) and
     * is supposed to stay constant */
    if (!IsFieldSet(FieldFirstSegment)) {
        SetFirstSegment(Segments.size() - 1);
        ResetField(FieldFirstSegment);
    }
    
    /* Fill in policy flags if some have been set */
    byte policy_val = PolicyList[0].type;
    if (SRPolicy::IsSet(policy_val)) {
        SetPolicyFlag1(policy_val);
        ResetField(FieldPolicyFlag1);
    }
    policy_val = PolicyList[1].type;
    if (SRPolicy::IsSet(policy_val)) {
        SetPolicyFlag2(policy_val);
        ResetField(FieldPolicyFlag2);
    }
    policy_val = PolicyList[2].type;
    if (SRPolicy::IsSet(policy_val)) {
        SetPolicyFlag3(policy_val);
        ResetField(FieldPolicyFlag3);
    }
    policy_val = PolicyList[3].type;
    if (SRPolicy::IsSet(policy_val)) {
        SetPolicyFlag4(policy_val);
        ResetField(FieldPolicyFlag4);
    
    }

    /* Extension header length is the number of groups of 8 bytes
     * after the first 8 bytes of the header,
     * which is only the payload in this case*/
    if (!IsFieldSet(FieldHeaderExtLen)) {
        SetHeaderExtLen(GetRoutingPayloadSize() / 8);
        ResetField(FieldHeaderExtLen);
    }

    /* Super class will take care of registering the payload and next header */
    IPv6RoutingHeader::Craft();
}

void IPv6SegmentRoutingHeader::ParsePolicy(const byte &policy_val,
        const byte &policy_index, byte const **segment_end) {
    /* Check if that policy is set*/
    if (SRPolicy::IsSet(policy_val)) {
        SRPolicy& policy = PolicyList[policy_index];
        /* Update the pointer towards the end of the segment section */ 
        *segment_end -= SRPolicy::SRPOLICY_SIZE; 
        /* Copy its type */
        policy.type = policy_val;
        /* Copy its value */
        policy.Read(*segment_end);
    }
}

void IPv6SegmentRoutingHeader::PushIPv6Segment(const string& ip) {
    segment_t segment;
    /* Convert the ip to bytes */
    inet_pton(AF_INET6, ip.c_str(), segment.s);
    /* Push it on the segment stack */
    Segments.push_back(segment);
}

void IPv6SegmentRoutingHeader::CopySegment(const byte *segment_start) {
    /* Allocate a buffer to store the IPv6 address */
    segment_t segment;
    /* Copy it */
    memcpy(segment.s, segment_start, SEGMENT_SIZE);
    /* Put it on the segments stack */
    Segments.push_back(segment);
}

void IPv6SegmentRoutingHeader::ParseLayerData(ParseInfo* info) {
    /* SRH is structured as FixedHeader/Segments/PolicyList/HMAC ,
     * where the last two part are optional */
    const byte *segment_start = info->raw_data + info->offset;
    const byte *segment_end = segment_start + GetHeaderExtLen() * 8;
    
    /* Check presence of the HMAC field at the end*/
    if (GetHMACKeyID()) {
        /* Update the pointer to the end of the segment section */
        segment_end -= HMAC_SIZE;
        /* Copy the HMAC field */
        memcpy(HMAC, segment_end, HMAC_SIZE);
    }
    
    /* Check, starting at the last one, for the presence of Policy data */
    ParsePolicy(GetPolicyFlag4(), 3, &segment_end);
    ParsePolicy(GetPolicyFlag3(), 2, &segment_end);
    ParsePolicy(GetPolicyFlag2(), 1, &segment_end);
    ParsePolicy(GetPolicyFlag1(), 0, &segment_end);

    /* Check the consistency of the packet */
    if (segment_start + SEGMENT_SIZE * (1 + GetFirstSegment()) != segment_end) {
        /* Inconsistent packet, abort*/
        PrintMessage(Crafter::PrintCodes::PrintError,
                "IPv6SegmentRoutingHeader::ParseLayerData()",
                "Inconsistency detected between FirstSegment and PolicyFlags/HMAC.");
        info->top = 1;
        return;
    }

    /* Finally parse all segments that are left */
    for (; segment_start < segment_end; segment_start += SEGMENT_SIZE)
        CopySegment(segment_start);

    /* We've processed the SR part of the header,
     * delegate the generic handling to the super class */
    IPv6RoutingHeader::ParseLayerData(info);
}

void IPv6SegmentRoutingHeader::PrintPayload(ostream& str) const {
    str << "Segment stack = [ ";
    vector<segment_t>::const_iterator it;
    for (it = Segments.begin(); it != Segments.end(); ++it) {
        char addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, it->s, addr, INET6_ADDRSTRLEN);
        str << addr << " , ";
    }
    str << "], ";
    if (SRPolicy::IsSet(GetPolicyFlag1()))
        PolicyList[0].Print(1, str);
    if (SRPolicy::IsSet(GetPolicyFlag2()))
        PolicyList[1].Print(2, str);
    if (SRPolicy::IsSet(GetPolicyFlag3()))
        PolicyList[2].Print(3, str);
    if (SRPolicy::IsSet(GetPolicyFlag1()))
        PolicyList[3].Print(4, str);
    if (GetHMACKeyID()) {
        str << "HMAC = ";
        str << hex;
        for (size_t i = 0; i < HMAC_SIZE; ++i) {
            if (!(i % 8)) str << " 0x"; 
            str << (int)HMAC[i];
        }
        str << dec << " ";
    }
}

