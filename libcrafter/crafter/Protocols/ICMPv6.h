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
#ifndef ICMPV6_H_
#define ICMPV6_H_

#include "ICMPv6Layer.h"

namespace Crafter {

    class ICMPv6: public ICMPv6Layer {

        void DefineProtocol();

		byte MapTypeNumber(short_word type);

        Constructor GetConstructor() const {
            return ICMPv6::ICMPv6ConstFunc;
        };

        static Layer* ICMPv6ConstFunc() {
            return new ICMPv6;
        };

        void Craft();

        std::string MatchFilter() const ;

        void ReDefineActiveFields();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldRestOfHeader = 3;
        static const byte FieldMTU = 4;
        static const byte FieldPointer = 5;
        static const byte FieldIdentifier = 6;
        static const byte FieldSequenceNumber = 7;
        static const byte FieldLength = 8;

    public:

        enum { PROTO = 0x3A01 };

		/* ------- Messages types --------- */

		/* +++ Error messages +++ */
		static const byte DestinationUnreachable;
		static const byte TimeExceeded;
		static const byte ParameterProblem;
		static const byte PacketTooBig;

		/* +++ Request and replies +++ */
		static const byte EchoRequest;
		static const byte EchoReply;

        ICMPv6();

        void SetRestOfHeader(const word& value) {
            SetFieldValue(FieldRestOfHeader,value);
        };

        void SetMTU(const word& value) {
            SetFieldValue(FieldMTU,value);
        };

        void SetPointer(const word& value) {
            SetFieldValue(FieldPointer,value);
        };

        void SetIdentifier(const short_word& value) {
            SetFieldValue(FieldIdentifier,value);
        };

        void SetSequenceNumber(const short_word& value) {
            SetFieldValue(FieldSequenceNumber,value);
        };

        void SetLength(const byte& value) {
            SetFieldValue(FieldLength,value);
        };

        word  GetRestOfHeader() const {
            return GetFieldValue<word>(FieldRestOfHeader);
        };

        word  GetMTU() const {
            return GetFieldValue<word>(FieldMTU);
        };

        word  GetPointer() const {
            return GetFieldValue<word>(FieldPointer);
        };

        short_word  GetIdentifier() const {
            return GetFieldValue<short_word>(FieldIdentifier);
        };

        short_word  GetSequenceNumber() const {
            return GetFieldValue<short_word>(FieldSequenceNumber);
        };

        byte  GetLength() const {
            return GetFieldValue<byte>(FieldLength);
        };

        ~ICMPv6() { /* Destructor */ };

    };

}

#endif /* ICMPV6_H_ */
