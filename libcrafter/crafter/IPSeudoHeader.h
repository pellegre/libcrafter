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


#ifndef IPSEUDOHEADER_H_
#define IPSEUDOHEADER_H_

#include "IP.h"

namespace Crafter {

	class IPSeudoHeader : public Layer {

	public:
		/* Constructor */
		IPSeudoHeader();

		/* Define the field of the IP layer */
		void DefineProtocol();

		Constructor GetConstructor() const {
			return IPSeudoHeader::IPSeudoHeaderConstFunc;
		};

		static Layer* IPSeudoHeaderConstFunc() {
			return new IPSeudoHeader;
		};

		/* Seters */

		void SetProtocolLength(short_word length) {
			SetFieldValue<word>("ProtocolLength",length);
		};

		void SetZeros(unsigned char zeros) {
			SetFieldValue<word>("Zeros",zeros);
		};

		void SetProtocol(unsigned char proto) {
			SetFieldValue<word>("Protocol",proto);
		};

		void SetSourceIP(std::string source_ip) {
			SetFieldValue<std::string>("SourceIP",source_ip);
		};

		void SetDestinationIP(std::string dst_ip) {
			SetFieldValue<std::string>("DestinationIP",dst_ip);
		};

		/* Getters */

		word GetProtocolLength() {
			return GetFieldValue<word>("ProtocolLength");
		};

		word GetProtocol() {
			return GetFieldValue<word>("Protocol");
		};

		std::string GetSourceIP() {
			return GetFieldValue<std::string>("SourceIP");
		};

		std::string GetDestinationIP() {
			return GetFieldValue<std::string>("DestinationIP");
		};

		/* Copy crafted packet to buffer_data */
		void Craft () {/* */};

		~IPSeudoHeader() {/* */};

	};

}
#endif /* IPSEUDOHEADER_H_ */
