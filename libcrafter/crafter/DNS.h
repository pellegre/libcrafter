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


#ifndef DNS_H_
#define DNS_H_

#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "Layer.h"
#include "RawLayer.h"

namespace Crafter {

	class DNS : public Layer {

		/* Strings for print Codes */
		static std::string flagsOpCode[];
		static std::string flagsRCode[];

		/* Bit Position for each bit-field of the header */
		static const byte BitQR = 15;
		static const byte BitAA = 10;
		static const byte BitTC = 9;
		static const byte BitRD = 8;
		static const byte BitRA = 7;
		static const byte BitAD = 5;
		static const byte BitCD = 4;

		void DefineProtocol();

		Constructor GetConstructor() const {
			return DNS::DNSConstFunc;
		};

		static Layer* DNSConstFunc() {
			return new DNS;
		};

		/* Copy crafted packet to buffer_data */
		void Craft ();

		/* Put data into LIBNET context */
		void LibnetBuild(libnet_t* l);

	public:

		/* Typical types */
		static const short_word TypeA = 0x0001;
		static const short_word TypeNS = 0x0002;
		static const short_word TypeCNAME = 0x0005;
		static const short_word TypeSOA = 0x0006;
		static const short_word TypeWKS = 0x000b;
		static const short_word TypePTR = 0x000c;
		static const short_word TypeMX = 0x000f;
		static const short_word TypeSRV = 0x0021;
		static const short_word TypeA6 = 0x0026;
		static const short_word TypeANY = 0x00ff;

		/* Typical class */
		static const short_word ClassIN = 0x0001;

		/* Constructor, define number of words and registration */
		DNS();

		DNS(const DNS& dns) : Layer(dns) {
			Queries = dns.Queries;
			Answers = dns.Answers;
			Authority = dns.Authority;
			Additional = dns.Additional;
		};

		/* Assignment operator of this class */
		DNS& operator=(const DNS& right) {
			/* Copy the particular data of this class */
			Queries = right.Queries;
			Answers = right.Answers;
			Authority = right.Authority;
			Additional = right.Additional;
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

			const DNS* right_ptr = dynamic_cast< const DNS* >(&right);
			DNS::operator=(*right_ptr);
			/* Call the assignment operator of the base class */
			Layer::operator=(right);
			/* Return */
			return *this;
		}

		/* Class for a DNSQuery */
		class DNSQuery {

			/* Name of the query */
			std::string qname;
			/* Type field */
			short_word qtype;
			/* Class of the query */
			short_word qclass;

			/* Compressed domain name */
			byte cqname[NS_MAXCDNAME];
			/* Size of the raw data of the query */
			size_t size;

			/* Compress the name of the Query into the buffer and return the number of bytes compressed */
			size_t Compress();

		public:

			/* Constructor */
			DNSQuery(const std::string& qname = "");

			/* Create the Query from raw data */
			DNSQuery(const byte* raw_data);

			/* Copy constructor */
			DNSQuery(const DNSQuery& query);

			/* Set type of the query */
			void SetType(short_word qtype);
			/* Set type class of the query */
			void SetClass(short_word qclass);
			/* Set name field from a string */
			void SetName(const std::string& qname);

			/* Get name filed of the query */
			std::string GetName() const;
			/* Get the type of the query */
			short_word GetType() const;
			/* Get the class of the query */
			short_word GetClass() const;
			/* Get the size of the raw data to be write on the net */
			size_t GetSize() const;

			/* Write raw data on the pointer */
			size_t Write(byte* data_ptr) const;

			/* Print the DNS Query */
			void Print() const;

			~DNSQuery() { /*  */ };
		};

		/* Class for a RR used for answers */
		class DNSAnswer {

			/* Name of the query */
			std::string qname;
			/* Type field */
			short_word qtype;
			/* Class of the query */
			short_word qclass;
			/* Time to live */
			word ttl;
			/* RData length */
			short_word rdatalength;
			/* Resource record data */
			std::string rdata;

			/* Compressed domain name and RR data */
			byte cqname[NS_MAXCDNAME];
			byte crdata[NS_MAXCDNAME];
			/* Length of the qname */
			size_t qnamelength;

			/* Size of the raw data of the RR */
			size_t size;

			/* Compress the name and data of the RR into the buffer and return the number of bytes compressed */
			size_t CompressName();
			size_t CompressRData();

		public:

			/* Constructor */
			DNSAnswer(const std::string& qname = "", const std::string& rdata = "");

			/* Create the Query from raw data */
			DNSAnswer(const byte* raw_data);

			/* Copy constructor */
			DNSAnswer(const DNSAnswer& ans);

			/* Set name field from a string */
			void SetName(const std::string& qname);
			/* Set type of the query */
			void SetType(short_word qtype);
			/* Set type class of the query */
			void SetClass(short_word qclass);
			/* Set Time to Live */
			void SetTTL(word ttl);
			/* Set RR Data */
			void SetRData(const std::string& rdata);

			/* Get name filed of the query */
			std::string GetName() const;
			/* Get the type of the query */
			short_word GetType() const;
			/* Get the class of the query */
			short_word GetClass() const;
			/* Get Time to Live */
			word GetTTL() const;
		    /* Get length of the RR data */
			short_word GetRDataLength() const;
			/* Get RR data */
			std::string GetRData() const;

			/* Get the size of the raw data to be write on the net */
			size_t GetSize() const;

			/* Write raw data on the pointer */
			size_t Write(byte* data_ptr) const;

			/* Print the DNS Query */
			void Print() const;

			~DNSAnswer() { /*  */ };
		};

		friend void SetContainerSection(std::vector<DNSAnswer>& container, ns_sect section, ns_msg* handle);

		/* Vector of Queries and Resource Records */
		std::vector<DNSQuery> Queries;
		std::vector<DNSAnswer> Answers;
		std::vector<DNSAnswer> Authority;
		std::vector<DNSAnswer> Additional;

		/* Operation Codes from bit 1 to 4 */
		static const byte OpCodeQuery = 0x0;
		static const byte OpCodeIQuery = 0x1;
		static const byte OpCodeStatus = 0x2;
		static const byte OpCodeNotify = 0x4;
		static const byte OpCodeUpdate = 0x5;

		/* Return Code from bit 12 to 15 */
		static const byte RCodeNoError = 0x0;
		static const byte RCodeFormatError = 0x1;
		static const byte RCodeServerFailure = 0x2;
		static const byte RCodeNameError = 0x3;
		static const byte RCodeRefused = 0x5;
		static const byte RCodeYXDomain = 0x6;
		static const byte RCodeYXRRSet = 0x7;
		static const byte RCodeNXRRSet = 0x8;
		static const byte RCodeNotAuth = 0x9;
		static const byte RCodeNotZone = 0x10;

		void SetIdentification(short_word id) {
			SetFieldValue<word>("Identification",id);
		};

		void SetFlags(short_word flags) {
			SetFieldValue<word>("Flags",flags);
		};

		void SetTotalQuestions(short_word questions) {
			SetFieldValue<word>("TotalQuestions",questions);
		};

		void SetTotalAnswer(short_word answers) {
			SetFieldValue<word>("TotalAnswer",answers);
		};

		void SetTotalAuthority(short_word auths) {
			SetFieldValue<word>("TotalAuthority",auths);
		};

		void SetTotalAdditional(short_word addits) {
			SetFieldValue<word>("TotalAdditional",addits);
		};

		/* --------------- Functions for manipulating flags --------------- */

		void SetQRFlag(short_word value);
		void SetOpCode(short_word value);
		void SetAAFlag(short_word value);
		void SetTCFlag(short_word value);
		void SetRDFlag(short_word value);
		void SetRAFlag(short_word value);
		void SetADFlag(short_word value);
		void SetCDFlag(short_word value);
		void SetRCode(short_word value);

		short_word GetQRFlag() const;
		short_word GetOpCode() const;
		short_word GetAAFlag() const;
		short_word GetTCFlag() const;
		short_word GetRDFlag() const;
		short_word GetRAFlag() const;
		short_word GetADFlag() const;
		short_word GetCDFlag() const;
		short_word GetRCode() const;

		/* ---------------------------------------------------------------- */

		short_word GetIdentification() const {
			return GetFieldValue<word>("Identification");
		};

		short_word GetFlags() const {
			return GetFieldValue<word>("Flags");
		};

		short_word GetTotalQuestions() const {
			return GetFieldValue<word>("TotalQuestions");
		};

		short_word GetTotalAnswer() const {
			return GetFieldValue<word>("TotalAnswer");
		};

		short_word GetTotalAuthority() const {
			return GetFieldValue<word>("TotalAuthority");
		};

		short_word GetTotalAdditional() const {
			return GetFieldValue<word>("TotalAdditional");
		};

		/* Override Print method */
		void Print() const;

		/* Set the field values from data of a Raw Layer */
		void FromRaw(const RawLayer& raw_layer);

		~DNS() { /* */ };

	};

}

#endif /* DNS_H_ */
