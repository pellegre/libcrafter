/*
Copyright (c) 2012, Bruno Nery
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

#include "Layer.h"

namespace Crafter {

    class ICMPExtensionObject : public Layer {
        /* Define the field of the IP layer */
        void DefineProtocol();

        Constructor GetConstructor() const {
            return ICMPExtensionObject::ICMPExtensionObjectConstFunc;
        };

        static Layer* ICMPExtensionObjectConstFunc() {
            return new ICMPExtensionObject;
        };

        /* Copy crafted packet to buffer_data */
        void Craft();

        /* Redefine active fields */
        void ReDefineActiveFields();

        /* Put Data into libnet context */
        void LibnetBuild(libnet_t* l);

        /* Match filter function */
        virtual std::string MatchFilter() const;

    public:
        /* Classes (ClassNum) */
        static const byte MPLS = 1;

        /* Types (CType) */
        /* +++ MPLS +++ */
        static const byte MPLSReserved = 0;
        static const byte MPLSIncoming = 1;

        /* Constructor */
        ICMPExtensionObject();

        /* Setters */
        void SetLength(word length) {
            SetFieldValueCheckOverlap<word>("Length", length);
        };

        void SetClassNum(unsigned char classnum) {
            SetFieldValueCheckOverlap<word>("ClassNum", classnum);
        };

        void SetCType(unsigned char ctype) {
            SetFieldValueCheckOverlap<word>("CType", ctype);
        };

        /* Getters */
        word GetLength() const {
            return GetFieldValue<word>("Length");
        };

        word GetClassNum() const {
            return GetFieldValue<word>("ClassNum");
        };

        std::string GetClassName() const {
            word classnum = GetClassNum();
            switch (classnum) {
            case MPLS: return "ICMPExtensionMPLS";
            default: return "";
            }
        };

        word GetCType() const {
            return GetFieldValue<word>("CType");
        };

        virtual ~ICMPExtensionObject();
    };

}

#endif /* ICMPEXTENSIONOBJECT_H_ */
