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
#ifndef ICMPEXTENSIONMPLS_H_
#define ICMPEXTENSIONMPLS_H_

#include "../Layer.h"

namespace Crafter {

    class ICMPExtensionMPLS: public Layer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return ICMPExtensionMPLS::ICMPExtensionMPLSConstFunc;
        };

        static Layer* ICMPExtensionMPLSConstFunc() {
            return new ICMPExtensionMPLS;
        };

        void Craft();

        void ReDefineActiveFields();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldLabel = 0;
        static const byte FieldExperimental = 1;
        static const byte FieldBottomOfStack = 2;
        static const byte FieldTTL = 3;

    public:

		enum { PROTO = 0xfd };

        ICMPExtensionMPLS();

        void SetLabel(const word& value) {
            SetFieldValue(FieldLabel,value);
        };

        void SetExperimental(const word& value) {
            SetFieldValue(FieldExperimental,value);
        };

        void SetBottomOfStack(const word& value) {
            SetFieldValue(FieldBottomOfStack,value);
        };

        void SetTTL(const byte& value) {
            SetFieldValue(FieldTTL,value);
        };

        word  GetLabel() const {
            return GetFieldValue<word>(FieldLabel);
        };

        word  GetExperimental() const {
            return GetFieldValue<word>(FieldExperimental);
        };

        word  GetBottomOfStack() const {
            return GetFieldValue<word>(FieldBottomOfStack);
        };

        byte  GetTTL() const {
            return GetFieldValue<byte>(FieldTTL);
        };

        ~ICMPExtensionMPLS() { /* Destructor */ };

    };

}

#endif /* ICMPEXTENSIONMPLS_H_ */
