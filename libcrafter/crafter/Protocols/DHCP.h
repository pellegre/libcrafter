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

    class DHCP: public Layer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return DHCP::DHCPConstFunc;
        };

        static Layer* DHCPConstFunc() {
            return new DHCP;
        };

        void Craft();

        void ReDefineActiveFields();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldOperationCode = 0;
        static const byte FieldHardwareType = 1;
        static const byte FieldHardwareLength = 2;
        static const byte FieldHopCount = 3;
        static const byte FieldTransactionID = 4;
        static const byte FieldNumberOfSeconds = 5;
        static const byte FieldFlags = 6;
        static const byte FieldClientIP = 7;
        static const byte FieldYourIP = 8;
        static const byte FieldServerIP = 9;
        static const byte FieldGatewayIP = 10;
        static const byte FieldClientMAC = 11;
        static const byte FieldZeroPadding = 12;
        static const byte FieldServerHostName = 13;
        static const byte FieldBootFile = 14;

        void PrintPayload(std::ostream& str) const;

    public:

		/* Some constant of the DHCP protocol */
		static const byte Request;
		static const byte Reply;

		enum { PROTO = 0xfff4 };

        DHCP();

		DHCP(const DHCP& dhcp) : Layer(dhcp) {
			/* Copy the Options */
			std::vector<DHCPOptions*>::const_iterator it_opt;

			for(it_opt = dhcp.Options.begin() ; it_opt != dhcp.Options.end() ; it_opt++)
				this->Options.push_back((*it_opt)->Clone());
		};

		/* Assignment operator of this class */
		DHCP& operator=(const DHCP& right) {

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
			if (GetName() != right.GetName())
				throw std::runtime_error("Cannot convert " + right.GetName() + " to " + GetName());

			const DHCP* right_ptr = dynamic_cast< const DHCP* >(&right);
			DHCP::operator=(*right_ptr);
			/* Call the assignment operator of the base class */
			Layer::operator=(right);
			/* Return */
			return *this;
		}

        void SetOperationCode(const byte& value) {
            SetFieldValue(FieldOperationCode,value);
        };

        void SetHardwareType(const byte& value) {
            SetFieldValue(FieldHardwareType,value);
        };

        void SetHardwareLength(const byte& value) {
            SetFieldValue(FieldHardwareLength,value);
        };

        void SetHopCount(const byte& value) {
            SetFieldValue(FieldHopCount,value);
        };

        void SetTransactionID(const word& value) {
            SetFieldValue(FieldTransactionID,value);
        };

        void SetNumberOfSeconds(const short_word& value) {
            SetFieldValue(FieldNumberOfSeconds,value);
        };

        void SetFlags(const short_word& value) {
            SetFieldValue(FieldFlags,value);
        };

        void SetClientIP(const std::string& value) {
            SetFieldValue(FieldClientIP,value);
        };

        void SetYourIP(const std::string& value) {
            SetFieldValue(FieldYourIP,value);
        };

        void SetServerIP(const std::string& value) {
            SetFieldValue(FieldServerIP,value);
        };

        void SetGatewayIP(const std::string& value) {
            SetFieldValue(FieldGatewayIP,value);
        };

        void SetClientMAC(const std::string& value) {
            SetFieldValue(FieldClientMAC,value);
        };

        void SetZeroPadding(const std::vector<byte> & value) {
            SetFieldValue(FieldZeroPadding,value);
        };

        void SetServerHostName(const std::string& value) {
            SetFieldValue(FieldServerHostName,value);
        };

        void SetBootFile(const std::string& value) {
            SetFieldValue(FieldBootFile,value);
        };

        byte  GetOperationCode() const {
            return GetFieldValue<byte>(FieldOperationCode);
        };

        byte  GetHardwareType() const {
            return GetFieldValue<byte>(FieldHardwareType);
        };

        byte  GetHardwareLength() const {
            return GetFieldValue<byte>(FieldHardwareLength);
        };

        byte  GetHopCount() const {
            return GetFieldValue<byte>(FieldHopCount);
        };

        word  GetTransactionID() const {
            return GetFieldValue<word>(FieldTransactionID);
        };

        short_word  GetNumberOfSeconds() const {
            return GetFieldValue<short_word>(FieldNumberOfSeconds);
        };

        short_word  GetFlags() const {
            return GetFieldValue<short_word>(FieldFlags);
        };

        std::string  GetClientIP() const {
            return GetFieldValue<std::string>(FieldClientIP);
        };

        std::string  GetYourIP() const {
            return GetFieldValue<std::string>(FieldYourIP);
        };

        std::string  GetServerIP() const {
            return GetFieldValue<std::string>(FieldServerIP);
        };

        std::string  GetGatewayIP() const {
            return GetFieldValue<std::string>(FieldGatewayIP);
        };

        std::string  GetClientMAC() const {
            return GetFieldValue<std::string>(FieldClientMAC);
        };

        std::vector<byte>   GetZeroPadding() const {
            return GetFieldValue<std::vector<byte> >(FieldZeroPadding);
        };

        std::string  GetServerHostName() const {
            return GetFieldValue<std::string>(FieldServerHostName);
        };

        std::string  GetBootFile() const {
            return GetFieldValue<std::string>(FieldBootFile);
        };

		/* DHCP Options */
		std::vector<DHCPOptions*> Options;

		/* Set the field values from data of a Raw Layer */
		void FromRaw(const RawLayer& raw_layer);

        ~DHCP() { /* Destructor */ };

    };

}

#endif /* DHCP_H_ */
