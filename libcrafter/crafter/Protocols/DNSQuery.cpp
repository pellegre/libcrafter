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

DNS::DNSQuery::DNSQuery(const string& qname) : qname(qname) {
	/* Check the size */
	if(qname.size() != 0) {
		/* Compress the name */
		size_t nbytes = Compress();
		/* Update the size of the raw data */
		size = 2 * sizeof(short_word) + nbytes;
	}
	SetType(DNS::TypeA);
	SetClass(DNS::ClassIN);
}

DNS::DNSQuery::DNSQuery(const DNSQuery& query) {
	for(size_t i = 0 ; i < NS_MAXCDNAME ; i++)
		cqname[i] = query.cqname[i];
	qtype = query.qtype;
	qclass = query.qclass;
	qname = query.qname;
	size = query.size;
}

void DNS::DNSQuery::SetClass(short_word _class) {
	qclass = _class;
}

void DNS::DNSQuery::SetType(short_word _type) {
	qtype = _type;
}

void DNS::DNSQuery::SetName(const string& _name) {
	qname = _name;
	/* Make the compression */
	size_t nbytes = Compress();
	/* Update the size of the raw data */
	size = 2 * sizeof(short_word) + nbytes;
}

string DNS::DNSQuery::GetName() const {
	return qname;
}

short_word DNS::DNSQuery::GetType() const {
	return qtype;
}

short_word DNS::DNSQuery::GetClass() const {
	return qclass;
}

size_t DNS::DNSQuery::GetSize() const {
	return size;
}

size_t DNS::DNSQuery::Compress() {
	/* Put data into the buffer */
	int nbytes = ns_name_compress(qname.c_str(),cqname,NS_MAXCDNAME,0,0);
	if(nbytes == -1)
		throw std::runtime_error("DNS::DNSQuery::Compress() : Error compressing the domain name provided");
	else
		return nbytes;

	return -1;
}

size_t DNS::DNSQuery::Write(byte* data_ptr) const {
	/* Write the query into the buffer, should correctly allocated */
	for(size_t i = 0 ; i < (size - 2 * sizeof(short_word)) ; i++) {
		data_ptr[i] = cqname[i];
	}

	data_ptr += (size - 2 * sizeof(short_word));
	/* Put type */
	ns_put16(qtype,data_ptr); data_ptr += sizeof(qtype);
	/* Put class */
	ns_put16(qclass,data_ptr); data_ptr += sizeof(qtype);

	return size;
}

void DNS::DNSQuery::Print() const {
	cout << "  < Query" << " (" << dec << GetSize() << " bytes) " << ":: ";
	cout << "QName = " <<  GetName() << " ; " ;
	cout << "Type = 0x" <<  hex << (unsigned int)(GetType()) << " ; " ;
	cout << "Class = 0x" <<  hex << (unsigned int)(GetClass()) << " " ;
	cout << "> ";
}


