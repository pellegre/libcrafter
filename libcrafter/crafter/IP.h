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
