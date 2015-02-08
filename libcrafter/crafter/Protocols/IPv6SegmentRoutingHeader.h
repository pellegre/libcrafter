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
#ifndef IPV6SEGMENTROUTINGHEADER_H_
#define IPV6SEGMENTROUTINGHEADER_H_

#include "../Layer.h"
#include "IPv6RoutingHeaderLayer.h"

namespace Crafter {

    class IPv6SegmentRoutingHeader: public IPv6RoutingHeaderLayer {
 
        Constructor GetConstructor() const {
            return IPv6SegmentRoutingHeader::IPv6SegmentRoutingHeaderConstFunc;
        };

        static Layer* IPv6SegmentRoutingHeaderConstFunc() {
            return new IPv6SegmentRoutingHeader;
        };

        void Craft();

        void DefineProtocol();

        void SetDefaultValues();

        void ParseLayerData(ParseInfo* info);

        void ParsePolicy(const byte &policy_val, const byte &policy_index,
                byte const **segment_end);

        void PrintPayload(std::ostream& str) const;

        byte* AllocateSegment() const;

        /* Generic routing header has fields 0-3  */
        static const byte FieldFirstSegment = 4;
        static const byte FieldCFlag = 5;
        static const byte FieldPFlag = 6;
        static const byte FieldReserved = 7;
        static const byte FieldPolicyFlag1 = 8;
        static const byte FieldPolicyFlag2 = 9;
        static const byte FieldPolicyFlag3 = 10;
        static const byte FieldPolicyFlag4 = 11;
        static const byte FieldHMACKeyID = 12;
   
    protected:

        size_t GetRoutingPayloadSize() const;

        void FillRoutingPayload(byte *payload) const;

    public:

        static const word PROTO = 0x2b04;

        IPv6SegmentRoutingHeader();

        IPv6SegmentRoutingHeader(const IPv6SegmentRoutingHeader& srh)
            : IPv6RoutingHeaderLayer(srh),
            Segments(srh.Segments) {
            memcpy(PolicyList, srh.PolicyList, sizeof(PolicyList));
            memcpy(HMAC, srh.HMAC, sizeof(HMAC));
        };

		/* Assignment operator of this class */
		IPv6SegmentRoutingHeader& operator=(const IPv6SegmentRoutingHeader& right) {
			/* Copy the particular data of this class */
            Segments = right.Segments;
            memcpy(HMAC, right.HMAC, sizeof(HMAC));
            memcpy(PolicyList, right.PolicyList, sizeof(PolicyList));
            /* Call the assignment operator of the base class */
			IPv6RoutingHeaderLayer::operator=(right);
			/* Return */
			return *this;
		}

		Layer& operator=(const Layer& right) {
			if (GetName() != right.GetName())
				throw std::runtime_error("Cannot convert " 
                        + right.GetName() + " to " + GetName());
			return IPv6SegmentRoutingHeader::operator=(
                    dynamic_cast<const IPv6SegmentRoutingHeader&>(right));
		}


        static const size_t SEGMENT_SIZE = sizeof(in6_addr);
        struct SRPolicy {
            static const byte SRPOLICY_UNSET = 0x0;
            static const byte SRPOLICY_INGRESS = 0x1;
            static const byte SRPOLICY_EGRESS = 0x2;
            static const byte SRPOLICY_SOURCE_ADDRESS = 0x3;

            /* Policies are 128bits long, opaque values, size of a segment */
            static const size_t SRPOLICY_SIZE = IPv6SegmentRoutingHeader::SEGMENT_SIZE;
            byte policy[SRPOLICY_SIZE];
            byte type;

            void SetIPv6(const IPv6Address &ip) { ip.Write(policy); }
            size_t GetSize() const { return type == SRPOLICY_UNSET ? 0 : SRPOLICY_SIZE; }
            void Write(byte *dst) const { memcpy(dst, policy, SRPOLICY_SIZE); }
            void Read(const byte *src) { memcpy(policy, src, SRPOLICY_SIZE); }
            void Print(const int& nr, std::ostream& str) const {
                char addr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, policy, addr, INET6_ADDRSTRLEN);
                str << "Policy " << nr << " = " << addr
                    << " (" << GetTypeDescr() << ") , ";
            }
            const char* GetTypeDescr() const {
                switch(type) {
                    case SRPOLICY_EGRESS: return "Egress router";
                    case SRPOLICY_INGRESS: return "Ingress router";
                    case SRPOLICY_SOURCE_ADDRESS: return "Original source address";
                }
                return "Unset";
            }

            SRPolicy() : type(SRPOLICY_UNSET) { memset(policy, 0, SRPOLICY_SIZE); }

            static bool IsSet(byte policy_val) { return policy_val != SRPOLICY_UNSET; }
        };

        typedef struct { byte s[SEGMENT_SIZE]; } segment_t;

        std::vector<segment_t> Segments;
        SRPolicy PolicyList[4];
        /* HMAC is 256b */
        byte HMAC[32];
        static const size_t HMAC_SIZE = sizeof(HMAC);

        void SetFirstSegment(const byte& value) {
            SetFieldValue(FieldFirstSegment,value);
        };

        void SetCFlag(const word& value) {
            SetFieldValue(FieldCFlag,value);
        };

        void SetPFlag(const word& value) {
            SetFieldValue(FieldPFlag,value);
        };

        void SetReserved(const word& value) {
            SetFieldValue(FieldReserved,value);
        };

        void SetPolicyFlag1(const word& value) {
            SetFieldValue(FieldPolicyFlag1,value);
        };

        void SetPolicyFlag2(const word& value) {
            SetFieldValue(FieldPolicyFlag2,value);
        };

        void SetPolicyFlag3(const word& value) {
            SetFieldValue(FieldPolicyFlag3,value);
        };

        void SetPolicyFlag4(const word& value) {
            SetFieldValue(FieldPolicyFlag4,value);
        };

        void SetHMACKeyID(const byte& value) {
            SetFieldValue(FieldHMACKeyID,value);
        };

        byte  GetFirstSegment() const {
            return GetFieldValue<byte>(FieldFirstSegment);
        };

        word  GetCFlag() const {
            return GetFieldValue<word>(FieldCFlag);
        };

        word  GetPFlag() const {
            return GetFieldValue<word>(FieldPFlag);
        };

        word  GetReserved() const {
            return GetFieldValue<word>(FieldReserved);
        };

        word  GetPolicyFlag1() const {
            return GetFieldValue<word>(FieldPolicyFlag1);
        };

        word  GetPolicyFlag2() const {
            return GetFieldValue<word>(FieldPolicyFlag2);
        };

        word  GetPolicyFlag3() const {
            return GetFieldValue<word>(FieldPolicyFlag3);
        };

        word  GetPolicyFlag4() const {
            return GetFieldValue<word>(FieldPolicyFlag4);
        };

        byte  GetHMACKeyID() const {
            return GetFieldValue<byte>(FieldHMACKeyID);
        };

        ~IPv6SegmentRoutingHeader() { }

        void PushIPv6Segment(const std::string& ip);

        void CopySegment(const byte *segment_start);

    };

}

#endif /* IPV6SEGMENTROUTINGHEADER_H_ */
