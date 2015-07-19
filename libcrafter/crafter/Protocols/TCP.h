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
#ifndef TCP_H_
#define TCP_H_

#include "../Layer.h"

namespace Crafter {

    class TCP: public Layer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return TCP::TCPConstFunc;
        };

        static Layer* TCPConstFunc() {
            return new TCP;
        };

        void Craft();

        std::string MatchFilter() const ;

        void ParseLayerData(ParseInfo* info);

        static const byte FieldSrcPort = 0;
        static const byte FieldDstPort = 1;
        static const byte FieldSeqNumber = 2;
        static const byte FieldAckNumber = 3;
        static const byte FieldDataOffset = 4;
        static const byte FieldReserved = 5;
        static const byte FieldFlags = 6;
        static const byte FieldWindowsSize = 7;
        static const byte FieldCheckSum = 8;
        static const byte FieldUrgPointer = 9;

    public:

		enum { PROTO = 0x06 };

		/* Flags */
		static const byte FIN;
		static const byte SYN;
		static const byte RST;
		static const byte PSH;
		static const byte ACK;
		static const byte URG;
		static const byte ECE;
		static const byte CWR;

		/* Flag Checkers */
		byte GetFIN() { return (GetFlags() & TCP::FIN); };
		byte GetSYN() { return (GetFlags() & TCP::SYN); };
		byte GetRST() { return (GetFlags() & TCP::RST); };
		byte GetPSH() { return (GetFlags() & TCP::PSH); };
		byte GetACK() { return (GetFlags() & TCP::ACK); };
		byte GetURG() { return (GetFlags() & TCP::URG); };
		byte GetECE() { return (GetFlags() & TCP::ECE); };
		byte GetCWR() { return (GetFlags() & TCP::CWR); };

        TCP();

        void SetSrcPort(const short_word& value) {
            SetFieldValue(FieldSrcPort,value);
        };

        void SetDstPort(const short_word& value) {
            SetFieldValue(FieldDstPort,value);
        };

        void SetSeqNumber(const word& value) {
            SetFieldValue(FieldSeqNumber,value);
        };

        void SetAckNumber(const word& value) {
            SetFieldValue(FieldAckNumber,value);
        };

        void SetDataOffset(const word& value) {
            SetFieldValue(FieldDataOffset,value);
        };

        void SetReserved(const word& value) {
            SetFieldValue(FieldReserved,value);
        };

        void SetFlags(const byte& value) {
            SetFieldValue(FieldFlags,value);
        };

        void SetWindowsSize(const short_word& value) {
            SetFieldValue(FieldWindowsSize,value);
        };

        void SetCheckSum(const short_word& value) {
            SetFieldValue(FieldCheckSum,value);
        };

        void SetUrgPointer(const short_word& value) {
            SetFieldValue(FieldUrgPointer,value);
        };

        short_word  GetSrcPort() const {
            return GetFieldValue<short_word>(FieldSrcPort);
        };

        short_word  GetDstPort() const {
            return GetFieldValue<short_word>(FieldDstPort);
        };

        word  GetSeqNumber() const {
            return GetFieldValue<word>(FieldSeqNumber);
        };

        word  GetAckNumber() const {
            return GetFieldValue<word>(FieldAckNumber);
        };

        word  GetDataOffset() const {
            return GetFieldValue<word>(FieldDataOffset);
        };

        word  GetReserved() const {
            return GetFieldValue<word>(FieldReserved);
        };

        byte  GetFlags() const {
            return GetFieldValue<byte>(FieldFlags);
        };

        short_word  GetWindowsSize() const {
            return GetFieldValue<short_word>(FieldWindowsSize);
        };

        short_word  GetCheckSum() const {
            return GetFieldValue<short_word>(FieldCheckSum);
        };

        short_word  GetUrgPointer() const {
            return GetFieldValue<short_word>(FieldUrgPointer);
        };

        ~TCP() { /* Destructor */ };

        /* Return the size of the following TCPOptions */
        size_t ComputeOptionSize() const;

    };

}

#endif /* TCP_H_ */
