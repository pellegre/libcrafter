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
	if(nbytes == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "DNSQuery::Compress()",
		             "Error compressing the domain name provided");
		exit(1);
		return -1;
	} else
		return nbytes;

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


