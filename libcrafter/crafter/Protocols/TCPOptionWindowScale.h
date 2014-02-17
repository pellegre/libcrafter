/*
Copyright (c) 2013, Gregory Detal
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

#ifndef TCPOPTIONWSCALE_H_
#define TCPOPTIONWSCALE_H_

#include "TCPOptionLayer.h"

namespace Crafter {

    class TCPOptionWindowScale: public TCPOptionLayer {

        Constructor GetConstructor() const {
            return TCPOptionWindowScale::TCPOptionWindowScaleConstFunc;
        };

        static Layer* TCPOptionWindowScaleConstFunc() {
            return new TCPOptionWindowScale;
        };

        void DefineProtocol();

        void Craft();

        void ReDefineActiveFields();

        static const byte FieldKind = 0;
        static const byte FieldLength = 1;
        static const byte FieldShift = 2;

    public:

        TCPOptionWindowScale();

        enum { PROTO = 0x9008 };

        void SetKind(const byte& value) {
            SetFieldValue(FieldKind,value);
        };

        void SetLength(const byte& value) {
            SetFieldValue(FieldLength,value);
        };

        void SetShift(const byte& value) {
            SetFieldValue(FieldShift,value);
        };

        byte  GetKind() const {
            return GetFieldValue<byte>(FieldKind);
        };

        byte  GetLength() const {
            return GetFieldValue<byte>(FieldLength);
        };

        byte  GetShift() const {
            return GetFieldValue<byte>(FieldShift);
        };

        ~TCPOptionWindowScale() { /* Destructor */ };

    };
}

#endif /* TCPOPTIONWSCALE */

