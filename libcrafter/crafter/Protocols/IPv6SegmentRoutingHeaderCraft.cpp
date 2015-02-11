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

#define forall_policies(i) for (size_t i = 0; i < policy_list_t::GetSize(); ++i)
// Will underflow at 0 so condition is sizeof(policylist)
#define forall_policies_reverse(i) for (size_t i = policy_list_t::GetSize() - 1; i < policy_list_t::GetSize(); --i)

size_t IPv6SegmentRoutingHeader::GetRoutingPayloadSize() const {
    /* Check if we don't already know the header length */
    size_t s = GetHeaderExtLen() * 8;
    if (s)
        return s;

    /* Base payload size is sum of segments size */
    s = Segments.size() * segment_t::GetSize();

    /* Check if we have some policy addresses set */
    forall_policies(policy) {
        if (PolicyIsSet(GetPolicyFlag(policy)))
            s += segment_t::GetSize();
    }

    /* HMAC field present iff HMACKeyID set */
    if (GetHMACKeyID())
        s += hmac_t::GetSize();
    return s;
}

void IPv6SegmentRoutingHeader::FillRoutingPayload(byte *payload) const {
    /* Put all segments at the start */
    vector<segment_t>::const_iterator it;
    for (it = Segments.begin(); it != Segments.end(); ++it, payload += segment_t::GetSize())
        it->Write(payload);

    /* Then the policy list */
    forall_policies(policy) {
        if (PolicyIsSet(GetPolicyFlag(policy))) {
            PolicyList[policy].Write(payload);
            payload += policy_t::GetSize();
        }
    }

    /* Then the HMAC */
    if (GetHMACKeyID()) {
        HMAC.Write(payload);
        payload += hmac_t::GetSize();
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

    /* Extension header length is the number of groups of 8 bytes
     * after the first 8 bytes of the header,
     * which is only the payload in this case */
    if (!IsFieldSet(FieldHeaderExtLen)) {
        SetHeaderExtLen(GetRoutingPayloadSize() / 8);
        ResetField(FieldHeaderExtLen);
    }

    /* Super class will take care of registering the payload and next header */
    IPv6RoutingHeader::Craft();
}

void IPv6SegmentRoutingHeader::ParsePolicy(
        const size_t &policy_index, byte const **segment_end) {
    /* Check if that policy is set*/
    if (PolicyIsSet(GetPolicyFlag(policy_index))) {
        /* Update the pointer towards the end of the segment section */
        *segment_end -= policy_t::GetSize();
        /* Copy its type */
        PolicyList[policy_index].Read(*segment_end);
    }
}

int IPv6SegmentRoutingHeader::PushIPv6Segment(const string& ip) {
    segment_t segment;
    /* Convert the ip to bytes */
    segment.ReadIPv6(ip);
    /* Push it on the segment stack */
    Segments.push_back(segment);
    return 0;
}

void IPv6SegmentRoutingHeader::CopySegment(const byte *segment_start) {
    /* Allocate a buffer to store the IPv6 address */
    segment_t segment;
    /* Copy it */
    segment.Read(segment_start);
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
        segment_end -= hmac_t::GetSize();
        /* Copy the HMAC field */
        HMAC.Read(segment_end);
    }

    /* Check, starting at the last one, for the presence of Policy data */
    forall_policies_reverse(policy) {
        ParsePolicy(policy, &segment_end);
    }

    /* Check the consistency of the packet */
    if (segment_start + segment_t::GetSize() * (1 + GetFirstSegment()) != segment_end) {
        /* Inconsistent packet, abort*/
        PrintMessage(Crafter::PrintCodes::PrintError,
                "IPv6SegmentRoutingHeader::ParseLayerData()",
                "Inconsistency detected between FirstSegment and PolicyFlags/HMAC.");
        info->top = 1;
        return;
    }

    /* Finally parse all segments that are left */
    for (; segment_start < segment_end; segment_start += segment_t::GetSize())
        CopySegment(segment_start);

    /* We've processed the SR part of the header,
     * delegate the generic handling to the super class */
    IPv6RoutingHeader::ParseLayerData(info);
}

void IPv6SegmentRoutingHeader::PrintPolicy(ostream &str, const size_t &index) const {
    str << "Policy " << index + 1 << " (" << GetPolicyDescr(index)
        << ") = " << PolicyList[index] << " , ";
}

void IPv6SegmentRoutingHeader::PrintPayload(ostream& str) const {
    str << "Segment stack = [ ";
    vector<segment_t>::const_iterator it;
    for (it = Segments.begin(); it != Segments.end(); ++it)
        str << *it << " , ";
    str << "], ";

    forall_policies(policy) {
        if (PolicyIsSet(GetPolicyFlag(policy)))
            PrintPolicy(str, policy);
    }

    if (GetHMACKeyID())
        str << "HMAC = " << HMAC;
}

int IPv6SegmentRoutingHeader::SetHMMAC(const byte &keyid, const hmac_t &hmac) {
    if (! keyid) {
        PrintMessage(Crafter::PrintCodes::PrintWarning,
                "IPv6SegmentRoutingHeader::SetHMAC()",
                "No valid keyid given -- ignoring HMAC.");
        return -1;
    }
    HMAC = hmac;
    return 0;
}

int IPv6SegmentRoutingHeader::SetPolicy(const size_t &index,
        const policy_t &policy, const policy_type_t &type) {
    if (!PolicyIsSet(type)) {
        PrintMessage(Crafter::PrintCodes::PrintWarning,
                "IPv6SegmentRoutingHeader::SetPolicy()",
                "No valid policy type given -- ignoring Policy.");
        return -1;
    }
    if (index >= policy_list_t::GetSize()) {
        PrintMessage(Crafter::PrintCodes::PrintWarning,
                "IPv6SegmentRoutingHeader::SetPolicy()",
                "PolicyIndex out of range -- ignoring Policy.");
        return -1;
    }

    PolicyList[index] = policy;
    SetPolicyFlag(index, type);

    return 0;
}
