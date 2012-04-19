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
