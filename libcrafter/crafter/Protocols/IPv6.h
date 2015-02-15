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
#ifndef IPV6_H_
#define IPV6_H_

#include "../Layer.h"
#include "IPLayer.h"

namespace Crafter {

    class IPv6: public IPLayer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return IPv6::IPv6ConstFunc;
        };

        static Layer* IPv6ConstFunc() {
            return new IPv6;
        };

        void Craft();

        std::string MatchFilter() const ;

        void ReDefineActiveFields();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldVersion = 0;
        static const byte FieldTrafficClass = 1;
        static const byte FieldFlowLabel = 2;
        static const byte FieldPayloadLength = 3;
        static const byte FieldNextHeader = 4;
        static const byte FieldHopLimit = 5;
        static const byte FieldSourceIP = 6;
        static const byte FieldDestinationIP = 7;

    public:

		enum { PROTO = 0x86dd };

        IPv6();

        void SetVersion(const word& value) {
            SetFieldValue(FieldVersion,value);
        };

        void SetTrafficClass(const word& value) {
            SetFieldValue(FieldTrafficClass,value);
        };

        void SetFlowLabel(const word& value) {
            SetFieldValue(FieldFlowLabel,value);
        };

        void SetPayloadLength(const short_word& value) {
            SetFieldValue(FieldPayloadLength,value);
        };

        void SetNextHeader(const byte& value) {
            SetFieldValue(FieldNextHeader,value);
        };

        void SetHopLimit(const byte& value) {
            SetFieldValue(FieldHopLimit,value);
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

        word  GetTrafficClass() const {
            return GetFieldValue<word>(FieldTrafficClass);
        };

        word  GetFlowLabel() const {
            return GetFieldValue<word>(FieldFlowLabel);
        };

        short_word  GetPayloadLength() const {
            return GetFieldValue<short_word>(FieldPayloadLength);
        };

        byte  GetNextHeader() const {
            return GetFieldValue<byte>(FieldNextHeader);
        };

        byte  GetHopLimit() const {
            return GetFieldValue<byte>(FieldHopLimit);
        };

        std::string  GetSourceIP() const {
            return GetFieldValue<std::string>(FieldSourceIP);
        };

        std::string  GetDestinationIP() const {
            return GetFieldValue<std::string>(FieldDestinationIP);
        };

	 byte* GetRawSourceIP() const {
            FieldInfo* ptr = Fields[FieldSourceIP];
            IPv6Address* ip =  dynamic_cast<IPv6Address*>(ptr);
            return (byte*) *ip;
        };
        
        byte* GetRawDestinationIP() const {
            FieldInfo* ptr = Fields[FieldDestinationIP];
            IPv6Address* ip =  dynamic_cast<IPv6Address*>(ptr);
            return (byte*) *ip;
        };

        /* Return the corresponding next header value for the given protoid */
        static short_word GetIPv6NextHeader(short_word transport_layer);

        /* Return the corresponding layer for the given network layer value */
        static Layer* GetNextLayer(ParseInfo *info, short_word network_layer);

        ~IPv6() { /* Destructor */ };

    };

}

#endif /* IPV6_H_ */
