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

#ifndef ICMPEXTENSION_H_
#define ICMPEXTENSION_H_

#include "Layer.h"

namespace Crafter {

    class ICMPExtension : public Layer {
        /* Define the field of the IP layer */
        void DefineProtocol();

        Constructor GetConstructor() const {
            return ICMPExtension::ICMPExtensionConstFunc;
        };

        static Layer* ICMPExtensionConstFunc() {
            return new ICMPExtension;
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
        /* Constructor */
        ICMPExtension();

        /* Setters */
        void SetVersion(unsigned char version) {
            GetLayerPtr<BitField<short_word,4,12> >("VerRes")->SetLowField(version);
            SetFieldValue<word>("VerRes",0);
        };

        void SetReserved(word reserved) {
            GetLayerPtr<BitField<short_word,4,12> >("VerRes")->SetHighField(reserved);
            SetFieldValue<word>("VerRes",0);
        };

        void SetChecksum(word checksum) {
            SetFieldValueCheckOverlap<word>("Checksum", checksum);
        };

        /* Getters */
        word GetVersion() const {
            return GetLayerPtr<BitField<short_word,4,12> >("VerRes")->GetLowField();
        };

        word GetReserved() const {
            return GetLayerPtr<BitField<short_word,4,12> >("VerRes")->GetHighField();
        };

        word GetChecksum() const {
            return GetFieldValue<word>("Checksum");
        };

        virtual ~ICMPExtension();
    };

}

#endif /* ICMPEXTENSION_H_ */
