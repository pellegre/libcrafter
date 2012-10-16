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
#ifndef ICMPEXTENSION_H_
#define ICMPEXTENSION_H_

#include "../Layer.h"

namespace Crafter {

    class ICMPExtension: public Layer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return ICMPExtension::ICMPExtensionConstFunc;
        };

        static Layer* ICMPExtensionConstFunc() {
            return new ICMPExtension;
        };

        void Craft();

        void ReDefineActiveFields();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldVersion = 0;
        static const byte FieldReserved = 1;
        static const byte FieldCheckSum = 2;

    public:

		enum { PROTO = 0xff };

        ICMPExtension();

        void SetVersion(const word& value) {
            SetFieldValue(FieldVersion,value);
        };

        void SetReserved(const word& value) {
            SetFieldValue(FieldReserved,value);
        };

        void SetCheckSum(const short_word& value) {
            SetFieldValue(FieldCheckSum,value);
        };

        word  GetVersion() const {
            return GetFieldValue<word>(FieldVersion);
        };

        word  GetReserved() const {
            return GetFieldValue<word>(FieldReserved);
        };

        short_word  GetCheckSum() const {
            return GetFieldValue<short_word>(FieldCheckSum);
        };

        ~ICMPExtension() { /* Destructor */ };

    };

}

#endif /* ICMPEXTENSION_H_ */
