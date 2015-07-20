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
#ifndef IPv6RoutingHeader_H_
#define IPv6RoutingHeader_H_

#include "../Layer.h"

namespace Crafter {

    class IPv6RoutingHeader: public Layer {

        Constructor GetConstructor() const {
            return IPv6RoutingHeader::IPv6RoutingHeaderConstFunc;
        };

        static Layer* IPv6RoutingHeaderConstFunc() {
            return new IPv6RoutingHeader;
        };

        void DefineProtocol();

        void SetDefaultValues();

    protected:
        virtual void Craft();

        virtual void ParseLayerData(ParseInfo* info);

        /* Return the size of the payload carried by this routing header */
        virtual size_t GetRoutingPayloadSize() const;

        /* Copy the raw data of the payload of this routing header */
        virtual void FillRoutingPayload(byte *payload) const;

        static const byte FieldNextHeader = 0;
        static const byte FieldHeaderExtLen = 1;
        static const byte FieldRoutingType = 2;
        static const byte FieldSegmentLeft = 3;

    public:

		enum { PROTO = 0x2b00 };

        IPv6RoutingHeader(const size_t &hdr_size=4,
                               const char *layer_name="IPv6RoutingHeader",
                               const word &proto_id=0x2b00,
                               const bool &reset_fields=true);

        IPv6RoutingHeader(const IPv6RoutingHeader &other)
            : Layer(other) {}

        IPv6RoutingHeader& operator=(const IPv6RoutingHeader &right) {
            Layer::operator=(right);
            return *this;
        }

        Layer& operator=(const Layer &right) {
            if (GetName() != right.GetName())
				throw std::runtime_error("Cannot convert " + right.GetName() + " to " + GetName());
			return IPv6RoutingHeader::operator=(dynamic_cast<const IPv6RoutingHeader&>(right));
        }

        void SetNextHeader(const byte& value) {
            SetFieldValue(FieldNextHeader,value);
        };

        void SetHeaderExtLen(const byte& value) {
            SetFieldValue(FieldHeaderExtLen,value);
        };

        void SetRoutingType(const byte& value) {
            SetFieldValue(FieldRoutingType,value);
        };

        void SetSegmentLeft(const byte& value) {
            SetFieldValue(FieldSegmentLeft,value);
        };

        byte  GetNextHeader() const {
            return GetFieldValue<byte>(FieldNextHeader);
        };

        byte  GetHeaderExtLen() const {
            return GetFieldValue<byte>(FieldHeaderExtLen);
        };

        byte  GetRoutingType() const {
            return GetFieldValue<byte>(FieldRoutingType);
        };

        byte  GetSegmentLeft() const {
            return GetFieldValue<byte>(FieldSegmentLeft);
        };

        /* Build IPv6RoutingHeader layer from type */
        static IPv6RoutingHeader* Build(int type);

        ~IPv6RoutingHeader() { /* Destructor */ };

    };

}

#endif /* IPv6RoutingHeader_H_ */
