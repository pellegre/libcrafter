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


#ifndef TCP_H_
#define TCP_H_

#include "Layer.h"
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
