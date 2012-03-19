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


#ifndef ARP_H_
#define ARP_H_

#include <string>
#include <iostream>
#include "Layer.h"

namespace Crafter {

	class ARP : public Layer{

		/* String of destination MAC address */
		std::string SenderMAC;
		/* String of source MAC address */
		std::string TargetMAC;

		/* Convert MAC address in string format to values for each field*/
		void SndMacStringToFields(const std::string& mac_address);
		void TrgMacStringToFields(const std::string& mac_address);

		/* Get values of each field an update MAC address */
		std::string SndMacFieldsToString();
		std::string TrgMacFieldsToString();

		void DefineProtocol();

		Constructor GetConstructor() const {
			return ARP::ARPConstFunc;
		};

		static Layer* ARPConstFunc() {
			return new ARP;
		};

		void Craft ();

		/* Redefine active fields */
		void ReDefineActiveFields();

		/* Put data into a libnet context calling de libnet_build* function */
		void LibnetBuild(libnet_t *l);

		virtual std::string MatchFilter() const;

	public:
		/* Operation Type */
		static const byte Request = 1;
		static const byte Reply = 2;

		static const std::string DefaultIP;
		static const std::string DefaultMAC;

		ARP();

		ARP(const ARP& arp) : Layer(arp) {
			TargetMAC = arp.TargetMAC;
			SenderMAC = arp.SenderMAC;
		};

		/* Assignament operator of this class */
		ARP& operator=(const ARP& right) {
			/* Copy the particular data of this class */
			TargetMAC = right.TargetMAC;
			SenderMAC = right.SenderMAC;
			/* Call the assignament operator of the base class */
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

			const ARP* right_ptr = dynamic_cast< const ARP* >(&right);
			ARP::operator=(*right_ptr);
			/* Call the assignament operator of the base class */
			Layer::operator=(right);
			/* Return */
			return *this;
		}

		/* Number of bytes on MAC address */
		static const int n_ether_bytes = 6;

		void SetSenderMAC(const std::string& dst) {
			SenderMAC = dst;
			SndMacStringToFields(dst);
		}

		void SetTargetMAC(const std::string& src) {
			TargetMAC = src;
			TrgMacStringToFields(src);
		}

		void SetHardwareType(short_word type) {
			SetFieldValue<word>("HardwareType",type);
		}

		void SetProtocolType(short_word type) {
			SetFieldValue<word>("ProtocolType",type);
		}

		void SetHardwareLength(short_word length) {
			SetFieldValue<word>("HardwareLength",length);
		}

		void SetProtocolLength(short_word length) {
			SetFieldValue<word>("ProtocolLength",length);
		}

		void SetSenderIP(std::string ip) {
			SetFieldValue<std::string>("SenderIP",ip);
		};

		void SetTargetIP(std::string ip) {
			SetFieldValue<std::string>("TargetIP",ip);
		};

		void SetOperation(short_word op) {
			SetFieldValue<word>("Operation",op);
		}

		std::string GetSenderMAC() const {
			//SenderMAC = SndMacFieldsToString();
			return SenderMAC;
		}

		std::string GetTargetMAC() const {
			//TargetMAC = TrgMacFieldsToString();
			return TargetMAC;
		}

		short_word GetHardwareType() const {
			return GetFieldValue<word>("HardwareType");
		}

		short_word  GetProtocolType() const  {
			return GetFieldValue<word>("ProtocolType");
		}

		short_word GetHardwareLength() const {
			return GetFieldValue<word>("HardwareLength");
		}

		short_word GetProtocolLength() const {
			return GetFieldValue<word>("ProtocolLength");
		}

		std::string GetSenderIP() const {
			return GetFieldValue<std::string>("SenderIP");
		};

		std::string GetTargetIP() const {
			return GetFieldValue<std::string>("TargetIP");
		};

		short_word GetOperation() const {
			return GetFieldValue<word>("Operation");
		}

		void Print() const;

		virtual ~ARP() {/* */};
	};

}

#endif /* ARP_H_ */
