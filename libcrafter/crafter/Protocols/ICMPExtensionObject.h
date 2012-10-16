/*
Copyright (c) 2012, Bruno Nery
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
#ifndef ICMPEXTENSIONOBJECT_H_
#define ICMPEXTENSIONOBJECT_H_

#include "../Layer.h"

namespace Crafter {

    class ICMPExtensionObject: public Layer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return ICMPExtensionObject::ICMPExtensionObjectConstFunc;
        };

        static Layer* ICMPExtensionObjectConstFunc() {
            return new ICMPExtensionObject;
        };

        void Craft();

        void ReDefineActiveFields();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldLength = 0;
        static const byte FieldClassNum = 1;
        static const byte FieldCType = 2;

    public:

		enum { PROTO = 0xfe };

        /* Classes (ClassNum) */
        static const byte MPLS;

        /* Types (CType) */
        /* +++ MPLS +++ */
        static const byte MPLSReserved;
        static const byte MPLSIncoming;

        ICMPExtensionObject();

        void SetLength(const short_word& value) {
            SetFieldValue(FieldLength,value);
        };

        void SetClassNum(const byte& value) {
            SetFieldValue(FieldClassNum,value);
        };

        void SetCType(const byte& value) {
            SetFieldValue(FieldCType,value);
        };

        short_word  GetLength() const {
            return GetFieldValue<short_word>(FieldLength);
        };

        byte  GetClassNum() const {
            return GetFieldValue<byte>(FieldClassNum);
        };

        byte  GetCType() const {
            return GetFieldValue<byte>(FieldCType);
        };

        std::string GetClassName() const;

        ~ICMPExtensionObject() { /* Destructor */ };

    };

}

#endif /* ICMPEXTENSIONOBJECT_H_ */
