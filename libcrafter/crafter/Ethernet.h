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


#ifndef ETHERNET_H_
#define ETHERNET_H_

#include <string>
#include <iostream>
#include "Layer.h"

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
