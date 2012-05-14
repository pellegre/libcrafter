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

#ifndef ICMPEXTENSIONMPLS_H_
#define ICMPEXTENSIONMPLS_H_

#include "Layer.h"

namespace Crafter {

    class ICMPExtensionMPLS : public Layer {
        /* Define the field of the IP layer */
        void DefineProtocol();

        Constructor GetConstructor() const {
            return ICMPExtensionMPLS::ICMPExtensionMPLSConstFunc;
        };

        static Layer* ICMPExtensionMPLSConstFunc() {
            return new ICMPExtensionMPLS;
        };

        /* Copy crafted packet to buffer_data */
        void Craft();

        /* Redefine active fields */
        void ReDefineActiveFields();

        /* Put Data into libnet context */
        void LibnetBuild(libnet_t* l);

        /* Match filter function */
        virtual std::string MatchFilter() const;

        void SetAll(word all) {
            SetFieldValueCheckOverlap<word>("LabelExpBosAndTTL", all);
        };

        word GetAll() const {
            return GetFieldValue<word>("LabelExpBosAndTTL");
        };

    public:
        /* Constructor */
        ICMPExtensionMPLS();

        /* Setters */
        void SetLabel(word label) {
            word all = GetAll();
            all &= 0x00000FFF;
            all |= ((label << 12) & 0xFFFFF000);
            SetAll(all);
        };

        void SetExperimental(unsigned char experimental) {
            word all = GetAll();
            all &= 0xFFFFF1FF;
            all |= ((experimental << 9) & 0x00000E00);
            SetAll(all);
        };

        void SetBottomOfStack(bool bottomofstack) {
            word all = GetAll();
            all &= 0xFFFFFEFF;
            all |= ((bottomofstack << 8) & 0x00000100);
            SetAll(all);
        };

        void SetTTL(unsigned char ttl) {
            word all = GetAll();
            all &= 0xFFFFFF00;
            all |= (ttl & 0x000000FF);
            SetAll(all);
        };

        /* Getters */
        word GetLabel() const {
            return (GetAll() & 0xFFFFF000) >> 12;
        };

        word GetExperimental() const {
            return (GetAll() & 0x00000E00) >> 9;
        };

        bool GetBottomOfStack() const {
            return (GetAll() & 0x00000100) >> 8;
        };

        word GetTTL() const {
            return (GetAll() & 0x000000FF);
        };

        /* Print the ICMP MPLS Extension Query */
        void Print() const;

        virtual ~ICMPExtensionMPLS();
    };

}

#endif /* ICMPEXTENSIONMPLS_H_ */
