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


#ifndef UDP_H_
#define UDP_H_

#include "Layer.h"
#include "IPSeudoHeader.h"

namespace Crafter {

	class UDP : public Layer {

		void DefineProtocol();

		Constructor GetConstructor() const {
			return UDP::UDPConstFunc;
		};

		static Layer* UDPConstFunc() {
			return new UDP;
		};

		/* Copy crafted packet to buffer_data */
		void Craft ();

		/* Put data into libnet context */
		void LibnetBuild(libnet_t* l);

		virtual std::string MatchFilter() const {
			char* src_port = new char[6];
			char* dst_port = new char[6];
			sprintf(src_port,"%d", GetSrcPort());
			sprintf(dst_port,"%d", GetDstPort());
			std::string ret_str = "udp and dst port " + std::string(src_port) + " and src port " + std::string(dst_port);
			delete [] src_port;
			delete [] dst_port;
			return ret_str;
		};

	public:
		/* Constructor, define number of words and registration */
		UDP();

		/* Set the source port */
		void SetSrcPort(short_word dst_port) {
			SetFieldValue<word>("SrcPort",dst_port);
		};

		/* Set the destination port */
		void SetDstPort(short_word src_port) {
			SetFieldValue<word>("DstPort",src_port);
		};

		/* Set the length of the packet */
		void SetLength(short_word length) {
			SetFieldValue<word>("Length",length);
		};

		/* Set the value of the checksum */
		void SetCheckSum(short_word checksum) {
			SetFieldValue<word>("CheckSum",checksum);
		};

		short_word  GetSrcPort() const {
			return GetFieldValue<word>("SrcPort");
		};

		/* Set the destination port */
		short_word  GetDstPort() const {
			return GetFieldValue<word>("DstPort");
		};

		/* Set the length of the packet */
		short_word  GetLength() const {
			return GetFieldValue<word>("Length");
		};

		/* Set the value of the checksum */
		short_word  GetCheckSum() const {
			return GetFieldValue<word>("CheckSum");
		};

		~UDP() { };

	};

}
#endif /* UDP_H_ */
