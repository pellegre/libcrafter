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
#ifndef TCPOPTION_H_
#define TCPOPTION_H_

#include "TCPOptionLayer.h"
#include "TCPOptionPad.h"

namespace Crafter {

    class TCPOption: public TCPOptionLayer {

        Constructor GetConstructor() const {
            return TCPOption::TCPOptionConstFunc;
        };

        static Layer* TCPOptionConstFunc() {
            return new TCPOption;
        };

    protected:

        void DefineProtocol();

        void Craft();

        void ReDefineActiveFields();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldKind = 0;
        static const byte FieldLength = 1;

    public:

        enum { PROTO = 0x9000 };

        /* Padding layers */
        static const TCPOptionPad NOP;
        static const TCPOptionPad EOL;

        TCPOption();

        void SetKind(const byte& value) {
            SetFieldValue(FieldKind,value);
        };

        void SetLength(const byte& value) {
            SetFieldValue(FieldLength,value);
        };

        byte  GetKind() const {
            return GetFieldValue<byte>(FieldKind);
        };

        byte  GetLength() const {
            return GetFieldValue<byte>(FieldLength);
        };

        ~TCPOption() { /* Destructor */ };

    };

    class TCPOptionSACKPermitted : public TCPOption {

    	Constructor GetConstructor() const {
            return TCPOptionSACKPermitted::TCPOptionSACKPermittedConstFunc;
        };

        static Layer* TCPOptionSACKPermittedConstFunc() {
            return new TCPOptionSACKPermitted;
        };

    public:

        TCPOptionSACKPermitted();

        enum { PROTO = 0x9004 };

        ~TCPOptionSACKPermitted() { /* Destructor */ };

    };

    class TCPOptionSACK : public TCPOption {

    	Constructor GetConstructor() const {
            return TCPOptionSACK::TCPOptionSACKConstFunc;
        };

        static Layer* TCPOptionSACKConstFunc() {
            return new TCPOptionSACK;
        };

        void PrintPayload(std::ostream& str) const;

    public:

        /* Structure to define a pair of left-right edges */
        struct Pair {
        	word left;
        	word right;
        	void Print(std::ostream& str) const;
        	Pair(word left, word right) : left(left), right(right) {/* */};
        	~Pair() {/* */};
        };

        TCPOptionSACK();

        enum { PROTO = 0x9005 };

        /* Methods to access the payload */
        std::vector<Pair> GetBlocks() const;
        void SetBlocks(const std::vector<Pair>& blocks);

        ~TCPOptionSACK() { /* Destructor */ };

    };
}

#endif /* TCPOPTION_H_ */
