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


#ifndef IP_H_
#define IP_H_

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include "Layer.h"

namespace Crafter {

	class IP : public Layer {

		/* Define the field of the IP layer */
		void DefineProtocol();

		Constructor GetConstructor() const {
			return IP::IPConstFunc;
		};

		static Layer* IPConstFunc() {
			return new IP;
		};

		/* Copy crafted packet to buffer_data */
		void Craft ();

		/* Put data into libnet context */
		void LibnetBuild(libnet_t* l);

		virtual std::string MatchFilter() const { return "ip and dst host " + GetSourceIP() + " and src host " + GetDestinationIP(); };

	public:

		static const std::string DefaultIP;

		IP();

		/* Seters */

		void SetVersion(unsigned char version) {
			GetLayerPtr<BitField<byte,4,4> >("VerHdr")->SetLowField(version);
			SetFieldValue<word>("VerHdr",0);
		};

		void SetHeaderLength(unsigned char length) {
			GetLayerPtr<BitField<byte,4,4> >("VerHdr")->SetHighField(length);
			SetFieldValue<word>("VerHdr",0);
		};

		void SetDifSerCP(short_word code) {
			SetFieldValue<word>("DifSerCP",code);
		};

		void SetTotalLength(short_word length) {
			SetFieldValue<word>("TotalLength",length);
		};

		void SetIdentification(short_word id) {
			SetFieldValue<word>("Identification",id);
		};

		void SetFlags(unsigned char flags) {
			GetLayerPtr<BitField<short_word,3,13> >("Off")->SetLowField(flags);
			SetFieldValue<word>("Off",0);
		};

		void SetFragmentOffset(short_word offset) {
			GetLayerPtr<BitField<short_word,3,13> >("Off")->SetHighField(offset);
			SetFieldValue<word>("Off",0);
		};

		void SetTTL(unsigned char ttl) {
			SetFieldValue<word>("TTL",ttl);
		};

		void SetProtocol(unsigned char proto) {
			SetFieldValue<word>("Protocol",proto);
		};

		void SetCheckSum(short_word checksum) {
			SetFieldValue<word>("CheckSum",checksum);
		};

		void SetSourceIP(std::string source_ip) {
			SetFieldValue<std::string>("SourceIP",source_ip);
		};

		void SetDestinationIP(std::string dst_ip) {
			SetFieldValue<std::string>("DestinationIP",dst_ip);
		};

		/* Getters */

		word GetVersion() const {
			return GetLayerPtr<BitField<byte,4,4> >("VerHdr")->GetLowField();
		};

		word GetHeaderLength() const {
			return GetLayerPtr<BitField<byte,4,4> >("VerHdr")->GetHighField();
		};

		word GetDifSerCP() const {
			return GetFieldValue<word>("DifSerCP");
		};

		word GetTotalLength() const {
			return GetFieldValue<word>("TotalLength");
		};

		word GetIdentification() const {
			return GetFieldValue<word>("Identification");
		};

		word GetFlags() const {
			return GetLayerPtr<BitField<short_word,3,13> >("Off")->GetLowField();
		}

		word GetFragmentOffset() const {
			return GetLayerPtr<BitField<short_word,3,13> >("Off")->GetHighField();
		};

		word GetTTL() const {
			return GetFieldValue<word>("TTL");
		};

		word GetProtocol() const {
			return GetFieldValue<word>("Protocol");
		};

		word GetCheckSum() const {
			return GetFieldValue<word>("CheckSum");
		};

		std::string GetSourceIP() const {
			return GetFieldValue<std::string>("SourceIP");
		};

		std::string GetDestinationIP() const {
			return GetFieldValue<std::string>("DestinationIP");
		};

		virtual ~IP() {/* */};
	};

}
#endif /* IP_H_ */
