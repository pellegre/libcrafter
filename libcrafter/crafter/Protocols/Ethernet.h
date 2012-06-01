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


#ifndef ETHERNET_H_
#define ETHERNET_H_

#include <string>
#include <iostream>
#include "../Layer.h"

namespace Crafter {

	class Ethernet : public Layer  {

		/* String of destination MAC address */
		std::string DestinationMAC;
		/* String of source MAC address */
		std::string SourceMAC;

		/* Convert MAC address in string format to values for each field*/
		void SrcMacStringToFields(const std::string& mac_address);
		void DstMacStringToFields(const std::string& mac_address);

		/* Get values of each field an update MAC address */
		std::string SrcMacFieldsToString();
		std::string DstMacFieldsToString();

		void Craft ();

		/* Redefine active fields */
		void ReDefineActiveFields();

		void LibnetBuild(libnet_t *l);

		void DefineProtocol();

		Constructor GetConstructor() const {
			return Ethernet::EthernetConstFunc;
		};

		static Layer* EthernetConstFunc() {
			return new Ethernet;
		};

	public:

		friend class Packet;

		static const std::string DefaultMAC;

		/* Number of bytes on MAC address */
		static const int n_ether_bytes = 6;

		Ethernet();

		Ethernet(const Ethernet& ether) : Layer(ether) {
			DestinationMAC = ether.DestinationMAC;
			SourceMAC = ether.SourceMAC;
		};

		/* Assignment operator of this class */
		Ethernet& operator=(const Ethernet& right) {
			/* Copy the particular data of this class */
			DestinationMAC = right.DestinationMAC;
			SourceMAC = right.SourceMAC;
			/* Call the assignment operator of the base class */
			Layer::operator=(right);
			/* Return */
			return *this;
		}

		Layer& operator=(const Layer& right) {

			/* Sanity check */
			if (GetName() != right.GetName()) {
				std::cout << "[!] ERROR: Cannot convert " << right.GetName()<< " to " << GetName() << std::endl;
				exit(1);
			}

			const Ethernet* right_ptr = dynamic_cast< const Ethernet* >(&right);
			Ethernet::operator=(*right_ptr);
			/* Call the assignment operator of the base class */
			Layer::operator=(right);
			/* Return */
			return *this;
		}

		void SetDestinationMAC(const std::string& dst) {
			DestinationMAC = dst;
			DstMacStringToFields(dst);
		}

		void SetSourceMAC(const std::string& src) {
			SourceMAC = src;
			SrcMacStringToFields(src);
		}

		void SetType(word type){
			SetFieldValue<word>("Type",type);
		}

		std::string GetDestinationMAC() const {
			//DestinationMAC = DstMacFieldsToString();
			return DestinationMAC;
		}

		std::string GetSourceMAC() const {
			//SourceMAC = SrcMacFieldsToString();
			return SourceMAC;
		}

		short_word GetType() const {
			return GetFieldValue<word>("Type");
		}

		void Print() const;

		virtual ~Ethernet() {/* */};
	};

}



#endif /* ETHERNET_H_ */
