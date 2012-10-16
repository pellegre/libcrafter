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
#ifndef ARP_H_
#define ARP_H_

#include "../Layer.h"

namespace Crafter {

    class ARP: public Layer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return ARP::ARPConstFunc;
        };

        static Layer* ARPConstFunc() {
            return new ARP;
        };

        void Craft();

        std::string MatchFilter() const ;

        void ReDefineActiveFields();

        static const byte FieldHardwareType = 0;
        static const byte FieldProtocolType = 1;
        static const byte FieldHardwareLength = 2;
        static const byte FieldProtocolLength = 3;
        static const byte FieldOperation = 4;
        static const byte FieldSenderMAC = 5;
        static const byte FieldSenderIP = 6;
        static const byte FieldTargetMAC = 7;
        static const byte FieldTargetIP = 8;

    public:
		/* Operation Type */
		static const byte Request = 1;
		static const byte Reply = 2;

		enum { PROTO = 0x0806 };

        ARP();

        void SetHardwareType(const short_word& value) {
            SetFieldValue(FieldHardwareType,value);
        };

        void SetProtocolType(const short_word& value) {
            SetFieldValue(FieldProtocolType,value);
        };

        void SetHardwareLength(const byte& value) {
            SetFieldValue(FieldHardwareLength,value);
        };

        void SetProtocolLength(const byte& value) {
            SetFieldValue(FieldProtocolLength,value);
        };

        void SetOperation(const short_word& value) {
            SetFieldValue(FieldOperation,value);
        };

        void SetSenderMAC(const std::string& value) {
            SetFieldValue(FieldSenderMAC,value);
        };

        void SetSenderIP(const std::string& value) {
            SetFieldValue(FieldSenderIP,value);
        };

        void SetTargetMAC(const std::string& value) {
            SetFieldValue(FieldTargetMAC,value);
        };

        void SetTargetIP(const std::string& value) {
            SetFieldValue(FieldTargetIP,value);
        };

        short_word  GetHardwareType() const {
            return GetFieldValue<short_word>(FieldHardwareType);
        };

        short_word  GetProtocolType() const {
            return GetFieldValue<short_word>(FieldProtocolType);
        };

        byte  GetHardwareLength() const {
            return GetFieldValue<byte>(FieldHardwareLength);
        };

        byte  GetProtocolLength() const {
            return GetFieldValue<byte>(FieldProtocolLength);
        };

        short_word  GetOperation() const {
            return GetFieldValue<short_word>(FieldOperation);
        };

        std::string  GetSenderMAC() const {
            return GetFieldValue<std::string>(FieldSenderMAC);
        };

        std::string  GetSenderIP() const {
            return GetFieldValue<std::string>(FieldSenderIP);
        };

        std::string  GetTargetMAC() const {
            return GetFieldValue<std::string>(FieldTargetMAC);
        };

        std::string  GetTargetIP() const {
            return GetFieldValue<std::string>(FieldTargetIP);
        };

        ~ARP() { /* Destructor */ };

    };

}

#endif /* ARP_H_ */
