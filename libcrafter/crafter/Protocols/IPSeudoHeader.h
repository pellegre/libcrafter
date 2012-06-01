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
