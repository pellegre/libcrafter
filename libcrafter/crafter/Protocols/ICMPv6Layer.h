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
#ifndef ICMPV6LAYER_H_
#define ICMPV6LAYER_H_

#include "../Layer.h"
#include "ICMPLayer.h"

namespace Crafter {

    class ICMPv6Layer: public ICMPLayer {

    protected:

        void DefineProtocol();

        void Craft();

        static const byte FieldType = 0;
        static const byte FieldCode = 1;
        static const byte FieldCheckSum = 2;

    public:

        enum { PROTO = 0x3A00 };

        ICMPv6Layer();

        void SetType(const byte& value) {
            SetFieldValue(FieldType,value);
        };

        void SetCode(const byte& value) {
            SetFieldValue(FieldCode,value);
        };

        void SetCheckSum(const short_word& value) {
            SetFieldValue(FieldCheckSum,value);
        };

        byte  GetType() const {
            return GetFieldValue<byte>(FieldType);
        };

        byte  GetCode() const {
            return GetFieldValue<byte>(FieldCode);
        };

        short_word  GetCheckSum() const {
            return GetFieldValue<short_word>(FieldCheckSum);
        };

        /* Build ICMPv6 layer from type */
        static ICMPv6Layer* Build(int type);

        ~ICMPv6Layer() { /* Destructor */ };

    };

}

#endif /* ICMPV6LAYER_H_ */
