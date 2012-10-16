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
#ifndef TCPOPTIONTIMESTAMP_H_
#define TCPOPTIONTIMESTAMP_H_

#include "TCPOptionLayer.h"

namespace Crafter {

    class TCPOptionTimestamp: public TCPOptionLayer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return TCPOptionTimestamp::TCPOptionTimestampConstFunc;
        };

        static Layer* TCPOptionTimestampConstFunc() {
            return new TCPOptionTimestamp;
        };

        void Craft();

        void ReDefineActiveFields();

        static const byte FieldKind = 0;
        static const byte FieldLength = 1;
        static const byte FieldValue = 2;
        static const byte FieldEchoReply = 3;

    public:

        enum { PROTO = 0x9002 };

        TCPOptionTimestamp();

        void SetKind(const byte& value) {
            SetFieldValue(FieldKind,value);
        };

        void SetLength(const byte& value) {
            SetFieldValue(FieldLength,value);
        };

        void SetValue(const word& value) {
            SetFieldValue(FieldValue,value);
        };

        void SetEchoReply(const word& value) {
            SetFieldValue(FieldEchoReply,value);
        };

        byte  GetKind() const {
            return GetFieldValue<byte>(FieldKind);
        };

        byte  GetLength() const {
            return GetFieldValue<byte>(FieldLength);
        };

        word  GetValue() const {
            return GetFieldValue<word>(FieldValue);
        };

        word  GetEchoReply() const {
            return GetFieldValue<word>(FieldEchoReply);
        };

        ~TCPOptionTimestamp() { /* Destructor */ };

    };

}

#endif /* TCPOPTIONTIMESTAMP_H_ */
