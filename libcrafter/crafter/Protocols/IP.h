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

#include "../Layer.h"
#include "IPLayer.h"

namespace Crafter {

    class IP: public IPLayer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return IP::IPConstFunc;
        };

        static Layer* IPConstFunc() {
            return new IP;
        };

        void Craft();

        std::string MatchFilter() const;

        void ReDefineActiveFields();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldVersion = 0;
        static const byte FieldHeaderLength = 1;
        static const byte FieldDiffServicesCP = 2;
        static const byte FieldExpCongestionNot = 3;
        static const byte FieldTotalLength = 4;
        static const byte FieldIdentification = 5;
        static const byte FieldFlags = 6;
        static const byte FieldFragmentOffset = 7;
        static const byte FieldTTL = 8;
        static const byte FieldProtocol = 9;
        static const byte FieldCheckSum = 10;
        static const byte FieldSourceIP = 11;
        static const byte FieldDestinationIP = 12;

    public:

		enum { PROTO = 0x0800 };

        IP();

        void SetVersion(const word& value) {
            SetFieldValue(FieldVersion,value);
        };

        void SetHeaderLength(const word& value) {
            SetFieldValue(FieldHeaderLength,value);
        };

        void SetDiffServicesCP(const word& value) {
            SetFieldValue(FieldDiffServicesCP,value);
        };

        void SetExpCongestionNot(const word& value) {
            SetFieldValue(FieldExpCongestionNot,value);
        };

        void SetTotalLength(const short_word& value) {
            SetFieldValue(FieldTotalLength,value);
        };

        void SetIdentification(const short_word& value) {
            SetFieldValue(FieldIdentification,value);
        };

        void SetFlags(const word& value) {
            SetFieldValue(FieldFlags,value);
        };

        void SetFragmentOffset(const word& value) {
            SetFieldValue(FieldFragmentOffset,value);
        };

        void SetTTL(const byte& value) {
            SetFieldValue(FieldTTL,value);
        };

        void SetProtocol(const byte& value) {
            SetFieldValue(FieldProtocol,value);
        };

        void SetCheckSum(const short_word& value) {
            SetFieldValue(FieldCheckSum,value);
        };

        void SetSourceIP(const std::string& value) {
            SetFieldValue(FieldSourceIP,value);
        };

        void SetDestinationIP(const std::string& value) {
            SetFieldValue(FieldDestinationIP,value);
        };

        word  GetVersion() const {
            return GetFieldValue<word>(FieldVersion);
        };

        word  GetHeaderLength() const {
            return GetFieldValue<word>(FieldHeaderLength);
        };

        word  GetDiffServicesCP() const {
            return GetFieldValue<word>(FieldDiffServicesCP);
        };

        word  GetExpCongestionNot() const {
            return GetFieldValue<word>(FieldExpCongestionNot);
        };

        short_word  GetTotalLength() const {
            return GetFieldValue<short_word>(FieldTotalLength);
        };

        short_word  GetIdentification() const {
            return GetFieldValue<short_word>(FieldIdentification);
        };

        word  GetFlags() const {
            return GetFieldValue<word>(FieldFlags);
        };

        word  GetFragmentOffset() const {
            return GetFieldValue<word>(FieldFragmentOffset);
        };

        byte  GetTTL() const {
            return GetFieldValue<byte>(FieldTTL);
        };

        byte  GetProtocol() const {
            return GetFieldValue<byte>(FieldProtocol);
        };

        short_word  GetCheckSum() const {
            return GetFieldValue<short_word>(FieldCheckSum);
        };

        std::string  GetSourceIP() const {
            return GetFieldValue<std::string>(FieldSourceIP);
        };
        
        std::string  GetDestinationIP() const {
            return GetFieldValue<std::string>(FieldDestinationIP);
        };

        byte* GetRawSourceIP() const {
            FieldInfo* ptr = Fields[FieldSourceIP];
            IPAddress* ip =  dynamic_cast<IPAddress*>(ptr);
            return (byte*) *ip;
        };
        
        byte* GetRawDestinationIP() const {
            FieldInfo* ptr = Fields[FieldDestinationIP];
            IPAddress* ip =  dynamic_cast<IPAddress*>(ptr);
            return (byte*) *ip;
        };
        
        ~IP() { /* Destructor */ };

    };

}

#endif /* IP_H_ */
