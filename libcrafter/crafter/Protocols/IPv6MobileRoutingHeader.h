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
#ifndef IPV6MOBILEROUTINGHEADER_H_
#define IPV6MOBILEROUTINGHEADER_H_

#include "../Layer.h"
#include "IPv6RoutingHeader.h"

namespace Crafter {

    class IPv6MobileRoutingHeader: public IPv6RoutingHeader {

        void DefineProtocol();

        void SetDefaultValues();

        Constructor GetConstructor() const {
            return IPv6MobileRoutingHeader::IPv6MobileRoutingHeaderConstFunc;
        };

        static Layer* IPv6MobileRoutingHeaderConstFunc() {
            return new IPv6MobileRoutingHeader;
        };

        void Craft();

        /* Generic routing header has field 0-3 */
        static const byte FieldReserved = 4;
        static const byte FieldHomeAddress = 5;

    protected:

        /* Everything is already included in the header */
        size_t GetRoutingPayloadSize() const { return 0; }
        /* Nothing to do here */
        void FillRoutingPayload(byte *payload) const { (void)payload; }

    public:

        enum { PROTO = 0x2b02 };

        IPv6MobileRoutingHeader();

        IPv6MobileRoutingHeader(const IPv6MobileRoutingHeader& mrh)
            : IPv6RoutingHeader(mrh) { };

		/* Assignment operator of this class */
		IPv6MobileRoutingHeader& operator=(const IPv6MobileRoutingHeader& right) {
			IPv6RoutingHeader::operator=(right);
            return *this;
		}

		Layer& operator=(const Layer& right) {
			if (GetName() != right.GetName())
				throw std::runtime_error("Cannot convert "
                        + right.GetName() + " to " + GetName());
			return IPv6MobileRoutingHeader::operator=(
                    dynamic_cast<const IPv6MobileRoutingHeader&>(right));
		}

        void SetReserved(const word& value) {
            SetFieldValue(FieldReserved,value);
        };

        void SetHomeAddress(const std::string& value) {
            SetFieldValue(FieldHomeAddress,value);
        };

        word  GetReserved() const {
            return GetFieldValue<word>(FieldReserved);
        };

        std::string  GetHomeAddress() const {
            return GetFieldValue<std::string>(FieldHomeAddress);
        };

        ~IPv6MobileRoutingHeader() { /* Destructor */ };

    };

}

#endif /* IPV6MOBILEROUTINGHEADER_H_ */
