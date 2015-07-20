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

        virtual void Craft();

        void ReDefineActiveFields();

        virtual void ParseLayerData(ParseInfo* info);

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

        virtual void SetLength(const byte& value) {
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

#ifndef TCPOPT_TFO_
#define TCPOPT_TFO 34
#endif

    class TCPOptionFastOpen : public TCPOption {

    	Constructor GetConstructor() const {
            return TCPOptionFastOpen::TCPOptionFastOpenConstFunc;
        };

        static Layer* TCPOptionFastOpenConstFunc() {
            return new TCPOptionFastOpen;
        };

    public:

        TCPOptionFastOpen();

        enum { PROTO = 0x9034 };

		unsigned int CookieLen() const {
			return GetPayloadSize();
		}

		void GetCookie(byte *dst) const {
			GetPayload(dst);
		}

		void setCookie(const byte *data, unsigned int ndata) {
			SetPayload(data, ndata);
		}

        ~TCPOptionFastOpen() { /* Destructor */ };

    };

#ifndef TCPOPT_EDO
#define TCPOPT_EDO  237 // 0x0EDO
#endif

	class TCPOptionEDO: public TCPOption {

        Constructor GetConstructor() const {
            return TCPOptionEDO::TCPEDOConstFunc;
        };

        static Layer* TCPEDOConstFunc() {
            return new TCPOptionEDO;
        };

        void Craft() { UpdateLengths(); };

        void ParseLayerData(ParseInfo* info);

        static const byte FieldKind = 0;
        static const byte FieldLength = 1;

		short_word header_length;
		short_word segment_length;

        void UpdateLengths();

		void PrintPayload(std::ostream& str) const;

    public:

        enum { PROTO = 0x900a };

		/* The different size in bytes for the EDO variant */
		static const byte EDOREQUEST;
		static const byte EDO;
		static const byte EDOEXT;

        TCPOptionEDO(byte length = TCPOptionEDO::EDOREQUEST);

		TCPOptionEDO(const TCPOptionEDO& edo) :
			header_length(edo.header_length),
			segment_length(edo.segment_length)
		{ SetLength(edo.GetLength()); }

		TCPOptionEDO& operator=(const TCPOptionEDO& right) {
			SetLength(right.GetLength());
			header_length = right.header_length;
			segment_length = right.segment_length;
			return *this;
		}

		Layer& operator=(const Layer& right) {
			if (GetName() != right.GetName())
				throw std::runtime_error("Cannot convert "
                        + right.GetName() + " to " + GetName());
			return TCPOptionEDO::operator=(
                    dynamic_cast<const TCPOptionEDO&>(right));
		}

        void SetLength(const byte& value) {
			if (value == TCPOptionEDO::EDOREQUEST
					|| value == TCPOptionEDO::EDO
					|| value == TCPOptionEDO::EDOEXT) {
				SetFieldValue(FieldLength,value);
			} else {
				PrintMessage(Crafter::PrintCodes::PrintWarning,
							"TCPOptionEDO::SetLength",
							"Requested Length is invalid, ignoring");
			}
        };

        short_word  GetHeaderLength() const {
            return header_length;
        };

		short_word  GetSegmentLength() const {
            return segment_length;
        };

		~TCPOptionEDO() { /* Destructor */ };
    };
}

#endif /* TCPOPTION_H_ */
