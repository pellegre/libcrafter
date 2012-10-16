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
#ifndef TCPOPTIONMAXSEGSIZE_H_
#define TCPOPTIONMAXSEGSIZE_H_

#include "TCPOptionLayer.h"

namespace Crafter {

    class TCPOptionMaxSegSize: public TCPOptionLayer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return TCPOptionMaxSegSize::TCPOptionMaxSegSizeConstFunc;
        };

        static Layer* TCPOptionMaxSegSizeConstFunc() {
            return new TCPOptionMaxSegSize;
        };

        void Craft();

        void ReDefineActiveFields();

        static const byte FieldKind = 0;
        static const byte FieldLength = 1;
        static const byte FieldMaxSegSize = 2;

    public:

        enum { PROTO = 0x9001 };

        TCPOptionMaxSegSize();

        void SetKind(const byte& value) {
            SetFieldValue(FieldKind,value);
        };

        void SetLength(const byte& value) {
            SetFieldValue(FieldLength,value);
        };

        void SetMaxSegSize(const short_word& value) {
            SetFieldValue(FieldMaxSegSize,value);
        };

        byte  GetKind() const {
            return GetFieldValue<byte>(FieldKind);
        };

        byte  GetLength() const {
            return GetFieldValue<byte>(FieldLength);
        };

        short_word  GetMaxSegSize() const {
            return GetFieldValue<short_word>(FieldMaxSegSize);
        };

        ~TCPOptionMaxSegSize() { /* Destructor */ };

    };

}

#endif /* TCPOPTIONMAXSEGSIZE_H_ */
