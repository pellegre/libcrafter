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

#ifndef DHCP_H_
#define DHCP_H_

#include "../Layer.h"
#include "RawLayer.h"
#include "DHCPOptions.h"

namespace Crafter {

	class DHCP : public Layer {

		/* String of client MAC address */
		std::string ClientMAC;
		/* Name of the boot file */
		std::string BootFileName;
		/* Server HostName */
		std::string ServerHostName;

		/* Convert MAC address in string format to values for each field*/
		void MacStringToFields(const std::string& mac_address);

		/* Get values of each field an update MAC address */
		std::string MacFieldsToString();

		void DefineProtocol();

		Constructor GetConstructor() const {
			return DHCP::DHCPConstFunc;
		};

		static Layer* DHCPConstFunc() {
			return new DHCP;
		};

		void Craft ();

		/* Put data into LIBNET context */
		void LibnetBuild(libnet_t* l);

	public:
		/* Number of bytes on MAC address */
		static const int n_ether_bytes = 6;

		DHCP();

		DHCP(const DHCP& dhcp) : Layer(dhcp) {
			ClientMAC = dhcp.ClientMAC;
			BootFileName = dhcp.BootFileName;
			ServerHostName = dhcp.ServerHostName;

			/* Copy the Options */
			std::vector<DHCPOptions*>::const_iterator it_opt;

			for(it_opt = dhcp.Options.begin() ; it_opt != dhcp.Options.end() ; it_opt++)
				this->Options.push_back((*it_opt)->Clone());
		};

		/* Assignment operator of this class */
		DHCP& operator=(const DHCP& right) {
			/* Copy the particular data of this class */
			ClientMAC = right.ClientMAC;
			BootFileName = right.BootFileName;
			ServerHostName = right.ServerHostName;

			/* Copy the Options */
			std::vector<DHCPOptions*>::const_iterator it_opt;

			/* Delete the current options */
			for(it_opt = Options.begin() ; it_opt != Options.end() ; it_opt++)
				delete (*it_opt);

			/* And copy the new ones */
			for(it_opt = right.Options.begin() ; it_opt != right.Options.end() ; it_opt++)
				this->Options.push_back((*it_opt)->Clone());

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

			const DHCP* right_ptr = dynamic_cast< const DHCP* >(&right);
			DHCP::operator=(*right_ptr);
			/* Call the assignment operator of the base class */
			Layer::operator=(right);
			/* Return */
			return *this;
		}

		/* Some constant of the DHCP protocol */
		static const byte Request = 0x1;
		static const byte Reply = 0x2;

		void SetOperationCode(byte value) {
			SetFieldValue<word>("OperationCode",value);
		};

		void SetHardwareType(byte value) {
			SetFieldValue<word>("HardwareType",value);
		};

		void SetHardwareLength(byte value) {
			SetFieldValue<word>("HardwareLength",value);
		};

		void SetHopCount(byte value) {
			SetFieldValue<word>("HopCount",value);
		};

		void SetTransactionID(word value) {
			SetFieldValue<word>("TransactionID",value);
		};

		void SetNumberOfSeconds(short_word value) {
			SetFieldValue<word>("NumberOfSeconds",value);
		};

		void SetFlags(short_word value) {
			SetFieldValue<word>("Flags",value);
		};

		void SetClientIP(std::string value) {
			SetFieldValue<std::string>("ClientIP",value);
		};

		void SetYourIP(std::string value) {
			SetFieldValue<std::string>("YourIP",value);
		};

		void SetServerIP(std::string value) {
			SetFieldValue<std::string>("ServerIP",value);
		};

		void SetGatewayIP(std::string value) {
			SetFieldValue<std::string>("GatewayIP",value);
		};

		void SetClientMAC(std::string value) {
			ClientMAC = value;
			MacStringToFields(value);
		}

		void SetBootFile(std::string filename) {
			BootFileName = filename;
		}

		void SetServerHostName(std::string servername) {
			ServerHostName = servername;
		}

		byte GetOperationCode() const {
			return GetFieldValue<word>("OperationCode");
		};

		byte GetHardwareType() const {
			return GetFieldValue<word>("HardwareType");
		};

		byte GetHardwareLength() const {
			return GetFieldValue<word>("HardwareLength");
		};

		byte GetHopCount() const {
			return GetFieldValue<word>("HopCount");
		};

		word GetTransactionID() const {
			return GetFieldValue<word>("TransactionID");
		};

		short_word GetNumberOfSeconds() const {
			return GetFieldValue<word>("NumberOfSeconds");
		};

		short_word GetFlags() const {
			return GetFieldValue<word>("Flags");
		};

		std::string GetClientIP() const {
			return GetFieldValue<std::string>("ClientIP");
		};

		std::string GetYourIP() const {
			return GetFieldValue<std::string>("YourIP");
		};

		std::string GetServerIP() const {
			return GetFieldValue<std::string>("ServerIP");
		};

		std::string GetGatewayIP() const {
			return GetFieldValue<std::string>("GatewayIP");
		};

		std::string GetClientMAC() const {
			return ClientMAC;
		}

		std::string GetBootFile() const {
			return BootFileName;
		}

		std::string GetServerHostName() const {
			return ServerHostName;
		}

		/* DHCP Options */
		std::vector<DHCPOptions*> Options;

		/* Set the field values from data of a Raw Layer */
		void FromRaw(const RawLayer& raw_layer);

		void Print() const;

		virtual ~DHCP();
	};

}

#endif /* DHCP_H_ */
