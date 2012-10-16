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
#ifndef IPOPTIONPAD_H_
#define IPOPTIONPAD_H_

#include "IPOptionLayer.h"

namespace Crafter {

    class IPOptionPad: public IPOptionLayer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return IPOptionPad::IPOptionPadConstFunc;
        };

        static Layer* IPOptionPadConstFunc() {
            return new IPOptionPad;
        };

        void Craft();

        void ReDefineActiveFields();

        static const byte FieldCopyFlag = 0;
        static const byte FieldClass = 1;
        static const byte FieldOption = 2;

    public:

        enum { PROTO = 0x5001 };

        IPOptionPad();

        void SetCopyFlag(const word& value) {
            SetFieldValue(FieldCopyFlag,value);
        };

        void SetClass(const word& value) {
            SetFieldValue(FieldClass,value);
        };

        void SetOption(const word& value) {
            SetFieldValue(FieldOption,value);
        };

        void SetLength(const byte& value) { /* NO length */ };

        word  GetCopyFlag() const {
            return GetFieldValue<word>(FieldCopyFlag);
        };

        word  GetClass() const {
            return GetFieldValue<word>(FieldClass);
        };

        word  GetOption() const {
            return GetFieldValue<word>(FieldOption);
        };

        byte  GetLength() const { return 1; }

        ~IPOptionPad() { /* Destructor */ };

    };

}

#endif /* IPOPTIONPAD_H_ */
