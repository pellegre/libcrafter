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


