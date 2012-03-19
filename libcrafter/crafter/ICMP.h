/*
Copyright (C) 2012 Pellegrino E.

This file is part of libcrafter

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
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
			SetFieldValue<word>("Type",type);
		};

		void SetCode(unsigned char code) {
			SetFieldValue<word>("Code",code);
		};

		void SetCheckSum(word checksum) {
			SetFieldValue<word>("CheckSum",checksum);
		};

		void SetRestOfHeader(word rest) {
			SetFieldValue<word>("RestOfHeader",rest);
		};

		/* Ping Header */
		void SetIdentifier(word rest) {
			SetFieldValue<word>("Identifier",rest);
		};

		void SetSequenceNumber(word rest) {
			SetFieldValue<word>("SequenceNumber",rest);
		};

		void SetPointer(word ptr) {
			SetFieldValue<word>("Pointer",ptr);
		};

		void SetGateway(std::string ip) {
			SetFieldValue<std::string>("Gateway",ip);
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

		virtual ~ICMP();
	};

}

#endif /* ICMP_H_ */
