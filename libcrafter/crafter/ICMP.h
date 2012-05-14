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


#ifndef ICMP_H_
#define ICMP_H_

#include "Layer.h"

namespace Crafter {

	class ICMP : public Layer {

		/* Define the field of the IP layer */
		void DefineProtocol();

		Constructor GetConstructor() const {
			return ICMP::ICMPConstFunc;
		};

		static Layer* ICMPConstFunc() {
			return new ICMP;
		};

		/* Copy crafted packet to buffer_data */
		void Craft ();

		/* Redefine active fields */
		void ReDefineActiveFields();

		/* Put Data into libnet context */
		void LibnetBuild(libnet_t* l);

		/* Match filetr function */
		virtual std::string MatchFilter() const;

	public:

		/* ------- Messages types --------- */

		/* +++ Other +++ */
		static const byte SourceQuench = 4;
		static const byte EchoRedirect = 5;

		/* +++ Error messages +++ */
		static const byte DestinationUnreachable = 3;
		static const byte TimeExceeded = 11;
		static const byte ParameterProblem = 12;

		/* +++ Request and replies +++ */
		static const byte EchoRequest = 8;
		static const byte EchoReply = 0;

		static const byte TimeStampRequest = 13;
		static const byte TimeStampReply = 14;

		static const byte InformationRequest = 15;
		static const byte InformationReply = 16;

		static const byte AddressMaskRequest = 17;
		static const byte AddressMaskReply = 18;

		/* Constructor */
		ICMP();

		/* Seters */
		void SetType(unsigned char type) {
			SetFieldValueCheckOverlap<word>("Type",type);
		};

		void SetCode(unsigned char code) {
			SetFieldValueCheckOverlap<word>("Code",code);
		};

		void SetCheckSum(word checksum) {
			SetFieldValueCheckOverlap<word>("CheckSum",checksum);
		};

		void SetRestOfHeader(word rest) {
			SetFieldValueCheckOverlap<word>("RestOfHeader",rest);
		};

		/* Ping Header */
		void SetIdentifier(word rest) {
			SetFieldValueCheckOverlap<word>("Identifier",rest);
		};

		void SetSequenceNumber(word rest) {
			SetFieldValueCheckOverlap<word>("SequenceNumber",rest);
		};

		void SetPointer(word ptr) {
			SetFieldValueCheckOverlap<word>("Pointer",ptr);
		};

		void SetGateway(std::string ip) {
			SetFieldValueCheckOverlap<std::string>("Gateway",ip);
		};

		/* RFC4884: Destination Unreachable, Time Exceeded and Parameter Problem */
		void SetLength(word length) {
			SetFieldValueCheckOverlap<word>("Length", length);
		};
                

		/* Geters */
		word GetType() const {
			return GetFieldValue<word>("Type");
		};

		word GetCode() const {
			return GetFieldValue<word>("Code");
		};

		word GetCheckSum() const {
			return GetFieldValue<word>("CheckSum");
		};

		word GetRestOfHeader() const {
			return GetFieldValue<word>("RestOfHeader");
		};

		/* Ping Header */
		word GetIdentifier() const {
			return  GetFieldValue<word>("Identifier");
		};

		word GetSequenceNumber() const {
			return GetFieldValue<word>("SequenceNumber");
		};

		word GetPointer() const {
			return GetFieldValue<word>("Pointer");
		};

		std::string GetGateway() const {
			return GetFieldValue<std::string>("Gateway");
		};

		/* RFC4884: Destination Unreachable, Time Exceeded and Parameter Problem */
		word GetLength() const {
			return  GetFieldValue<word>("Length");
		};

		virtual ~ICMP();
	};

}

#endif /* ICMP_H_ */
