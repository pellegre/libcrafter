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
#include "IPv6RoutingHeader.h"

namespace Crafter {

    class IPv6SegmentRoutingHeader: public IPv6RoutingHeader {

    public:
        template<class T, size_t n>
        class FixedSizeArray {
            /* This class assumes that both arrays are of equal length */
            FixedSizeArray& Clone(const FixedSizeArray &other) {
                for (size_t i = 0; i < n; ++i)
                    items[i] = other[i];
                return *this;
            }

            T items[n];

            public:
                FixedSizeArray() {}
                ~FixedSizeArray() {}
                /* copy */
                FixedSizeArray(const FixedSizeArray &other) { Clone(other); }
                FixedSizeArray& operator=(const FixedSizeArray other) { return Clone(other); }
                /* get/set */
                T operator[](int i) const { return items[i]; }
                T& operator[](int i) { return items[i]; }

                static size_t GetSize() { return n; }
        };

        template<size_t n>
        class ByteArray {

            ByteArray& Clone(const ByteArray &other) { Read(other.bytes); return *this; }

            protected:
                byte bytes[n];

            public:
                ByteArray() { memset(bytes, 0, n); }
                ~ByteArray() {}
                /* copy */
                ByteArray(const ByteArray &other) { Clone(other); }
                ByteArray(const byte *array) { Read(array); }
                /* set */
                ByteArray& operator=(const ByteArray &other) { return Clone(other); }
                ByteArray& operator=(const byte *other) { return Read(other); }
                byte operator[](int i) const { return bytes[i]; }
                byte& operator[](int i) { return bytes[i]; }

                void Write(byte *dst) const { memcpy(dst, bytes, n); }
                void Read(const byte *src) { memcpy(bytes, src, n); }
                byte* Raw() const { return bytes; }

                virtual void Print(std::ostream &str) const {
                    /* Each byte will be 0-padded, in hex */
                    str << std::hex;
                    for (size_t i = 0; i < n; ++i) {
                        /* group by 4 bytes */
                        if (!(i % 4)) str << " ";
                        str << std::setfill('0') << std::setw(2) << (int)bytes[i];
                    }
                    /* Restore stream state */
                    str << std::dec;
                }

                static size_t GetSize() { return n; }

                friend std::ostream& operator<<(std::ostream &str,
                        const ByteArray &array) {
                    array.Print(str);
                    return str;
                }
        };

        class IPv6ByteArray : public ByteArray<sizeof(in6_addr)> {
        public:
            IPv6ByteArray() : ByteArray() {}
            IPv6ByteArray(const IPv6ByteArray &other) : ByteArray(other) {}
            IPv6ByteArray(const std::string &ip) : ByteArray() { ReadIPv6(ip); }
            IPv6ByteArray(const char *ip) : ByteArray() { ReadIPv6(ip); }

            IPv6ByteArray& operator=(const std::string &ip) { ReadIPv6(ip); return *this; }
            IPv6ByteArray& operator=(const char *ip) { ReadIPv6(ip); return *this; }

            int ReadIPv6(const std::string &ip) {
                if (inet_pton(AF_INET6, ip.c_str(), bytes) <= 0) {
                    PrintMessage(Crafter::PrintCodes::PrintError,
                            "IPv6SegmentRoutingHeader::IPv6ByteArray::ReadIPv6()",
                            "<" + ip + "> is not a valid IPv6 address");
                    return -1;
                }
                return 0;
            }
            void Print(std::ostream &str) const {
                char addr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, bytes, addr, INET6_ADDRSTRLEN);
                str << addr;
            }
        };

        /* Segments are IPv6 addresses */
        typedef IPv6ByteArray segment_t;

        /* HMAC is 256b */
        typedef ByteArray< 256 / 8 > hmac_t;

        /* Policies are size of an IPv6, 128b opaque values */
        typedef IPv6ByteArray policy_t;
        /* Types of policies */
        typedef enum {
            POLICY_UNSET = 0x0,
            POLICY_INGRESS = 0x1,
            POLICY_EGRESS = 0x2,
            POLICY_SOURCE_ADDRESS = 0x3
        } policy_type_t;

        /* At present we only have 4 policies in the header at max (see flags) */
        typedef FixedSizeArray<policy_t, 4> policy_list_t;

    private:

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

        void ParsePolicy(const size_t &policy_index,
                         byte const **segment_end);

        void PrintPolicy(std::ostream &str, const size_t &index) const;

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

        enum { PROTO = 0x2b04 };

        std::vector<segment_t> Segments;

        policy_list_t PolicyList;

        hmac_t HMAC;

        IPv6SegmentRoutingHeader();

        IPv6SegmentRoutingHeader(const IPv6SegmentRoutingHeader& srh)
            : IPv6RoutingHeader(srh),
            Segments(srh.Segments),
            PolicyList(srh.PolicyList),
            HMAC(srh.HMAC) {};

		/* Assignment operator of this class */
		IPv6SegmentRoutingHeader& operator=(const IPv6SegmentRoutingHeader& right) {
			/* Copy the particular data of this class */
            Segments = right.Segments;
            PolicyList = right.PolicyList;
            HMAC = right.HMAC;
            /* Call the assignment operator of the base class */
			IPv6RoutingHeader::operator=(right);
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

        void SetPolicyFlag(const size_t &policy_index, const word &value)  {
            SetFieldValue(FieldPolicyFlag1 + policy_index, value);
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

        word GetPolicyFlag(const size_t &policy_index) const {
            return GetFieldValue<word>(FieldPolicyFlag1 + policy_index);
        };

        ~IPv6SegmentRoutingHeader() { }

        int PushIPv6Segment(const std::string& ip);

        int SetPolicy(const size_t &index, const policy_t &policy,
                const policy_type_t &type);

        int SetHMMAC(const byte &keyid, const hmac_t &hmac);

        void CopySegment(const byte *segment_start);

        void PrintPayload(std::ostream& str) const;

        static bool PolicyIsSet(const word &policy_type) {
            return (policy_type != POLICY_UNSET);
        }

        const char* GetPolicyDescr(const size_t &index) const {
            switch(GetPolicyFlag(index)) {
                case POLICY_EGRESS: return "Egress router";
                case POLICY_INGRESS: return "Ingress router";
                case POLICY_SOURCE_ADDRESS: return "Original source address";
                case POLICY_UNSET: return "Unset";
            }
            return "Invalid";
        }
    };

}

#endif /* IPV6SEGMENTROUTINGHEADER_H_ */
