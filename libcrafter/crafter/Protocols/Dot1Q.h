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
#ifndef Dot1Q_H_
#define Dot1Q_H_

#include "../Layer.h"

namespace Crafter {

    class Dot1Q: public Layer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return Dot1Q::Dot1QConstFunc;
        };

        static Layer* Dot1QConstFunc() {
            return new Dot1Q;
        };

        void Craft();

        void ReDefineActiveFields();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldPCP = 0;
        static const byte FieldDEI = 1;
        static const byte FieldVID = 2;
        static const byte FieldType = 3;

    public:

		enum { PROTO = 0x8100 };

        Dot1Q();

        void SetPCP(const word& value) {
            SetFieldValue(FieldPCP,value);
        };

        void SetDEI(const word& value) {
            SetFieldValue(FieldDEI,value);
        };

        void SetVID(const word& value) {
            SetFieldValue(FieldVID,value);
        };

        void SetType(const short_word& value) {
            SetFieldValue(FieldType,value);
        };

        word  GetPCP() const {
            return GetFieldValue<word>(FieldPCP);
        };

        word  GetDEI() const {
            return GetFieldValue<word>(FieldDEI);
        };

        word  GetVID() const {
            return GetFieldValue<word>(FieldVID);
        };

        short_word  GetType() const {
            return GetFieldValue<short_word>(FieldType);
        };

        ~Dot1Q() { /* Destructor */ };

    };

}

#endif /* Dot1Q_H_ */
