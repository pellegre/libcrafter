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


#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "DNS.h"

using namespace std;
using namespace Crafter;

DNS::DNSAnswer::DNSAnswer(const string& qname, const string& rdata) : qname(qname), rdata(rdata) {
	/* Check the size */
	if(qname.size() != 0) {
		/* Compress the name */
		qnamelength = CompressName();
		rdatalength = CompressRData();
		/* Update the size of the raw data */
		size = 3 * sizeof(short_word) + sizeof(word) + qnamelength + rdatalength;
	}
	SetType(DNS::TypeA);
	SetClass(DNS::ClassIN);
	SetTTL(0x58);
}

DNS::DNSAnswer::DNSAnswer(const DNSAnswer& ans) {
	for(size_t i = 0 ; i < NS_MAXCDNAME ; i++) {
		cqname[i] = ans.cqname[i];
		crdata[i] = ans.crdata[i];
	}
	qname = ans.qname;
	qtype = ans.qtype;
	qclass = ans.qclass;
	ttl = ans.ttl;
	rdatalength = ans.rdatalength;
	rdata = ans.rdata;

	qnamelength = ans.qnamelength;
	size = ans.size;
}

void DNS::DNSAnswer::SetClass(short_word _class) {
	qclass = _class;
}

void DNS::DNSAnswer::SetTTL(word _ttl) {
	ttl = _ttl;
}

void DNS::DNSAnswer::SetType(short_word _type) {
	qtype = _type;
}

void DNS::DNSAnswer::SetName(const string& _name) {
	qname = _name;
	/* Make the compression */
	qnamelength = CompressName();
	/* Update the size of the raw data */
	size = 3 * sizeof(short_word) + sizeof(word) + qnamelength + rdatalength;
}

void DNS::DNSAnswer::SetRData(const string& _rdata) {
	rdata = _rdata;
	/* Make the compression */
	rdatalength = CompressRData();
	/* Update the size of the raw data */
	size = 3 * sizeof(short_word) + sizeof(word) + qnamelength + rdatalength;
}

string DNS::DNSAnswer::GetName() const {
	return qname;
}

short_word DNS::DNSAnswer::GetType() const {
	return qtype;
}

short_word DNS::DNSAnswer::GetClass() const {
	return qclass;
}

word DNS::DNSAnswer::GetTTL() const {
	return ttl;
}

short_word DNS::DNSAnswer::GetRDataLength() const {
	return rdatalength;
}

size_t DNS::DNSAnswer::GetSize() const {
	return size;
}

string DNS::DNSAnswer::GetRData() const {
	return rdata;
}

size_t DNS::DNSAnswer::CompressName() {
	/* Put data into the buffer */
	int nbytes = ns_name_compress(qname.c_str(),cqname,NS_MAXCDNAME,0,0);
	if(nbytes == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "DNSAnswer::CompressName()",
		             "Error compressing the domain name provided");
		exit(1);
		return -1;
	} else
		return nbytes;

}

size_t DNS::DNSAnswer::CompressRData() {
	if (rdata.find_first_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIKKLMNOPQRSTUVWXYZ") != std::string::npos) {
		/* Put data into the buffer */
		int nbytes = ns_name_compress(rdata.c_str(),crdata,NS_MAXCDNAME,0,0);
		if(nbytes == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
						 "DNSAnswer::CompressRData()",
						 "Error compressing the domain name provided");
			exit(1);
			return -1;
		} else
			return nbytes;

	} else {
		ns_put32(inet_network(rdata.c_str()),crdata);
		return sizeof(word);
	}

}

size_t DNS::DNSAnswer::Write(byte* data_ptr) const {
	/* Write the query into the buffer, should be correctly allocated */
	for(size_t i = 0 ; i < qnamelength ; i++) {
		data_ptr[i] = cqname[i];
	}

	data_ptr += qnamelength;
	/* Put type */
	ns_put16(qtype,data_ptr); data_ptr += sizeof(qtype);
	/* Put class */
	ns_put16(qclass,data_ptr); data_ptr += sizeof(qtype);
	/* Put TTL */
	ns_put32(ttl,data_ptr); data_ptr += sizeof(ttl);
	/* Put RR data length */
	ns_put16(rdatalength,data_ptr); data_ptr += sizeof(rdatalength);

	for(size_t i = 0 ; i < rdatalength ; i++) {
		data_ptr[i] = crdata[i];
	}

	return size;
}

void DNS::DNSAnswer::Print() const {
	cout << "  < Answer" << " (" << dec << GetSize() << " bytes) " << ":: ";
	cout << "QName = " <<  GetName() << " ; " ;
	cout << "Type = 0x" <<  hex << (unsigned int)(GetType()) << " ; " ;
	cout << "Class = 0x" <<  hex << (unsigned int)(GetClass()) << " ; " ;
	cout << "TTL = 0x" << hex << GetTTL() << " ; " ;
	cout << "RDataLength = " << dec << GetRDataLength() << " ; " ;
	cout << "RData = " <<  GetRData() << " " ;
	cout << "> ";
}


