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

#include "config.h"
#include "DNS.h"

using namespace std;
using namespace Crafter;

#ifndef HAVE_INET_NETWORK
/* Taken from libbind 6.0 inet/inet_network.c */
/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

u_long
inet_network(register const char *cp)
{
	register u_long val, base, n, i;
	register char c;
	u_long parts[4], *pp = parts;
	int digit;

again:
	val = 0; base = 10; digit = 0;
	if (*cp == '0')
		digit = 1, base = 8, cp++;
	if (*cp == 'x' || *cp == 'X')
		base = 16, cp++;
	while ((c = *cp) != 0) {
		if (isdigit((unsigned char)c)) {
			if (base == 8U && (c == '8' || c == '9'))
				return (INADDR_NONE);
			val = (val * base) + (c - '0');
			cp++;
			digit = 1;
			continue;
		}
		if (base == 16U && isxdigit((unsigned char)c)) {
			val = (val << 4) +
			      (c + 10 - (islower((unsigned char)c) ? 'a' : 'A'));
			cp++;
			digit = 1;
			continue;
		}
		break;
	}
	if (!digit)
		return (INADDR_NONE);
	if (pp >= parts + 4 || val > 0xffU)
		return (INADDR_NONE);
	if (*cp == '.') {
		*pp++ = val, cp++;
		goto again;
	}
	if (*cp && !isspace(*cp&0xff))
		return (INADDR_NONE);
	*pp++ = val;
	n = pp - parts;
	if (n > 4U)
		return (INADDR_NONE);
	for (val = 0, i = 0; i < n; i++) {
		val <<= 8;
		val |= parts[i] & 0xff;
	}
	return (val);
}
#endif

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
	memcpy(cqname, ans.cqname, NS_MAXCDNAME);
	memcpy(crdata, ans.crdata, NS_MAXCDNAME);
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
	if(nbytes == -1)
		throw std::runtime_error("DNSAnswer::CompressName() : Error compressing the domain name provided");
	else
		return nbytes;

	return -1;


}

size_t DNS::DNSAnswer::CompressRData() {
	if (rdata.find_first_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIKKLMNOPQRSTUVWXYZ") != std::string::npos) {
		/* Put data into the buffer */
		int nbytes = ns_name_compress(rdata.c_str(),crdata,NS_MAXCDNAME,0,0);
		if(nbytes == -1)
			throw std::runtime_error("DNSAnswer::CompressRData() : Error compressing the domain name provided");
		else
			return nbytes;

		return -1;

	} else {
		ns_put32(inet_network(rdata.c_str()),crdata);
		return sizeof(word);
	}

}

size_t DNS::DNSAnswer::Write(byte* data_ptr) const {
	/* Write the query into the buffer, should be correctly allocated */
	memcpy(data_ptr, cqname, qnamelength);

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

void DNS::DNSAnswer::Print(std::ostream &out) const {
	out << "  < Answer" << " (" << dec << GetSize() << " bytes) " << ":: ";
	out << "QName = " <<  GetName() << " ; " ;
	out << "Type = 0x" <<  hex << (unsigned int)(GetType()) << " ; " ;
	out << "Class = 0x" <<  hex << (unsigned int)(GetClass()) << " ; " ;
	out << "TTL = 0x" << hex << GetTTL() << " ; " ;
	out << "RDataLength = " << dec << GetRDataLength() << " ; " ;
	out << "RData = " <<  GetRData() << " " ;
	out << "> ";
}


