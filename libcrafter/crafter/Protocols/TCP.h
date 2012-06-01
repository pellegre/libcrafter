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
#include "IPSeudoHeader.h"

namespace Crafter {

	class TCP : public Layer {

		/* Copy crafted packet to buffer_data */
		void Craft ();

		/* Put data into libnet context */
		void LibnetBuild(libnet_t* l);

		virtual std::string MatchFilter() const {
			char* src_port = new char[6];
			char* dst_port = new char[6];
			sprintf(src_port,"%d", GetSrcPort());
			sprintf(dst_port,"%d", GetDstPort());
			std::string ret_str = "tcp and dst port " + std::string(src_port) + " and src port " + std::string(dst_port);
			delete [] src_port;
			delete [] dst_port;
			return ret_str;
		};

		void DefineProtocol();

		Constructor GetConstructor() const {
			return TCP::TCPConstFunc;
		};

		static Layer* TCPConstFunc() {
			return new TCP;
		};

	public:
		/* Flags */
		static const byte FIN = 1 << 0;
		static const byte SYN = 1 << 1;
		static const byte RST = 1 << 2;
		static const byte PSH = 1 << 3;
		static const byte ACK = 1 << 4;
		static const byte URG = 1 << 5;
		static const byte ECE = 1 << 6;
		static const byte CWR = 1 << 7;

		/* Constructor, define number of words and registration */
		TCP();

		/* Flag Checkers */
		byte GetFIN() { return (GetFlags() & TCP::FIN); };
		byte GetSYN() { return (GetFlags() & TCP::SYN); };
		byte GetRST() { return (GetFlags() & TCP::RST); };
		byte GetPSH() { return (GetFlags() & TCP::PSH); };
		byte GetACK() { return (GetFlags() & TCP::ACK); };
		byte GetURG() { return (GetFlags() & TCP::URG); };
		byte GetECE() { return (GetFlags() & TCP::ECE); };
		byte GetCWR() { return (GetFlags() & TCP::CWR); };

		/* Set the source port */
		void SetSrcPort(short_word dst_port) {
			SetFieldValue<word>("SrcPort",dst_port);
		};

		/* Set the destination port */
		void SetDstPort(short_word src_port) {
			SetFieldValue<word>("DstPort",src_port);
		};

		void SetSeqNumber(word seq) {
			SetFieldValue<word>("SeqNumber",seq);
		};

		void SetAckNumber(word ack) {
			SetFieldValue<word>("AckNumber",ack);
		};

		void SetDataOffset(byte offset) {
			GetLayerPtr<BitField<byte,4,4> >("OffRes")->SetLowField(offset);
			SetFieldValue<word>("OffRes",0);
		};

		void SetReserved(byte reserved) {
			GetLayerPtr<BitField<byte,4,4> >("OffRes")->SetHighField(reserved);
			SetFieldValue<word>("OffRes",0);
		};

		void SetFlags(word flags) {
			SetFieldValue<word>("Flags",flags);
		};


		void SetWindowsSize(word wsize) {
			SetFieldValue<word>("WindowsSize",wsize);
		};

		void SetCheckSum(word checksum) {
			SetFieldValue<word>("CheckSum",checksum);
		};

		void SetUrgPointer(word checksum) {
			SetFieldValue<word>("CheckSum",checksum);
		};

		short_word  GetSrcPort() const {
			return GetFieldValue<word>("SrcPort");
		};

		/* Set the destination port */
		short_word  GetDstPort() const {
			return GetFieldValue<word>("DstPort");
		};

		word GetSeqNumber() const {
			return GetFieldValue<word>("SeqNumber");
		};

		word GetAckNumber() const {
			return GetFieldValue<word>("AckNumber");
		};

		word GetDataOffset() const {
			return GetLayerPtr<BitField<byte,4,4> >("OffRes")->GetLowField();
		}

		word GetReserved() const {
			return GetLayerPtr<BitField<byte,4,4> >("OffRes")->GetHighField();
		};

		word GetFlags() const {
			return GetFieldValue<word>("Flags");
		};

		word GetWindowsSize() const {
			return GetFieldValue<word>("WindowsSize");
		};

		word GetCheckSum() const {
			return GetFieldValue<word>("CheckSum");
		};

		word GetUrgPointer() const {
			return GetFieldValue<word>("UrgPointer");
		};

		virtual ~TCP() { /*  */ };
	};

}

#endif /* TCP_H_ */
