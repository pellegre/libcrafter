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


#include "DNS.h"
#include "../Utils/BitHandling.h"
#include <arpa/inet.h>

using namespace std;
using namespace Crafter;

std::string DNS::flagsOpCode[] = {
		"Query",
		"IQuery",
		"Status",
		" ", /* Reserved */
		"Notify",
		"Update",
		" ",
		" ",
		" ",
		" ",
		" ",
		" ",
		" ",
		" ",
		" ",
		" ",
};

std::string DNS::flagsRCode[] = {
		"NoError",
		"FormatError",
		"ServerFailure",
		"NameError",
		" ", /* Not implemented */
		"Refused",
		"YXDomain",
		"YXRRSet",
		"NXRRSet",
		"NotAuth",
		"NotZone",
		" " /* Extensions not implemented */
		" ",
		" ",
		" ",
		" ",
};

Crafter::DNS::DNS() {
	/* Allocate three words - just for the header */
	allocate_words(3);
	/* Name of the protocol represented by this layer */
	SetName("DNS");
	/* Set the protocol ID */
	SetprotoID(0xfff3);

	/* Creates field information for the layer */
	DefineProtocol();

	/* Always set default values for fields in a layer */
	SetIdentification(0);

	SetFlags(0);
	SetRDFlag(1);

	SetTotalQuestions(0);
	SetTotalAnswer(0);
	SetTotalAuthority(0);
	SetTotalAdditional(0);

	/* Always call this, reset all fields */
	ResetFields();
}

void DNS::DefineProtocol() {
	define_field("Identification",new NumericField(0,0,15));
	define_field("Flags",new NumericField(0,16,31));
	define_field("TotalQuestions",new NumericField(1,0,15));
	define_field("TotalAnswer",new NumericField(1,16,31));
	define_field("TotalAuthority",new NumericField(2,0,15));
	define_field("TotalAdditional",new NumericField(2,16,31));
}

void DNS::SetQRFlag(short_word value) {
	short_word old_value = GetFlags();
	if(value) old_value = SetBit(old_value,BitQR);
	else old_value = ResetBit(old_value,BitQR);
	SetFlags(old_value);
}
void DNS::SetOpCode(short_word value) {
	short_word old_value = GetFlags();
	old_value = ClearRange(old_value,11,14);
	value = ShiftLeft(value,11);
	old_value |= value;
	SetFlags(old_value);
}

void DNS::SetAAFlag(short_word value) {
	short_word old_value = GetFlags();
	if(value) old_value = SetBit(old_value,BitAA);
	else old_value = ResetBit(old_value,BitAA);
	SetFlags(old_value);
}

void DNS::SetTCFlag(short_word value) {
	short_word old_value = GetFlags();
	if(value) old_value = SetBit(old_value,BitTC);
	else old_value = ResetBit(old_value,BitTC);
	SetFlags(old_value);
}

void DNS::SetRDFlag(short_word value) {
	short_word old_value = GetFlags();
	if(value) old_value = SetBit(old_value,BitRD);
	else old_value = ResetBit(old_value,BitRD);
	SetFlags(old_value);
}

void DNS::SetRAFlag(short_word value) {
	short_word old_value = GetFlags();
	if(value) old_value = SetBit(old_value,BitRA);
	else old_value = ResetBit(old_value,BitRA);
	SetFlags(old_value);
}

void DNS::SetADFlag(short_word value) {
	short_word old_value = GetFlags();
	if(value) old_value = SetBit(old_value,BitAD);
	else old_value = ResetBit(old_value,BitAD);
	SetFlags(old_value);
}

void DNS::SetCDFlag(short_word value) {
	short_word old_value = GetFlags();
	if(value) old_value = SetBit(old_value,BitCD);
	else old_value = ResetBit(old_value,BitCD);
	SetFlags(old_value);
}

void DNS::SetRCode(short_word value) {
	short_word old_value = GetFlags();
	old_value = ClearRange(old_value,0,3);
	old_value |= value;
	SetFlags(old_value);
}

short_word DNS::GetQRFlag() const {
	return TestBit(GetFlags(),BitQR);
}

short_word DNS::GetOpCode() const {
	short_word flag = GetFlags();
	flag = ClearComplementRange(flag,11,14);
	flag = ShiftRight(flag,11);
	return flag;
}

short_word DNS::GetAAFlag() const {
	return TestBit(GetFlags(),BitAA);
}

short_word DNS::GetTCFlag() const {
	return TestBit(GetFlags(),BitTC);
}

short_word DNS::GetRDFlag() const {
	return TestBit(GetFlags(),BitRD);
}

short_word DNS::GetRAFlag() const {
	return TestBit(GetFlags(),BitRA);
}

short_word DNS::GetADFlag() const {
	return TestBit(GetFlags(),BitAD);
}

short_word DNS::GetCDFlag() const {
	return TestBit(GetFlags(),BitCD);
}

short_word DNS::GetRCode() const {
	short_word flag = GetFlags();
	flag = ClearComplementRange(flag,0,3);
	return flag;
}

void DNS::Craft() {
	/* Set the number of Queries */
	if (!IsFieldSet("TotalQuestions")) {
		SetTotalQuestions(Queries.size());
		ResetField("TotalQuestions");
	}

	/* Set the number of Answers */
	if (!IsFieldSet("TotalAnswer")) {
		SetTotalAnswer(Answers.size());
		ResetField("TotalAnswer");
	}

	/* Set the number of Authority data */
	if (!IsFieldSet("TotalAuthority")) {
		SetTotalAuthority(Authority.size());
		ResetField("TotalAuthority");
	}

	/* Set the number of Additional data */
	if (!IsFieldSet("TotalAdditional")) {
		SetTotalAdditional(Additional.size());
		ResetField("TotalAdditional");
	}

	/* Iterate through each Query to get the total size of the payload */
	vector<DNSQuery>::iterator it_query;
	size_t payload_size = 0;

	for(it_query  = Queries.begin() ; it_query != Queries.end() ; it_query++)
		payload_size += (*it_query).GetSize();

	/* Iterate through each Answer to get the total size of the payload */
	vector<DNSAnswer>::iterator it_ans;

	for(it_ans  = Answers.begin() ; it_ans != Answers.end() ; it_ans++)
		payload_size += (*it_ans).GetSize();

	/* Iterate through each Authority to get the total size of the payload */
	vector<DNSAnswer>::iterator it_auth;

	for(it_auth  = Authority.begin() ; it_auth != Authority.end() ; it_auth++)
		payload_size += (*it_auth).GetSize();

	/* Iterate through each Additional to get the total size of the payload */
	vector<DNSAnswer>::iterator it_add;

	for(it_add  = Additional.begin() ; it_add != Additional.end() ; it_add++)
		payload_size += (*it_add).GetSize();

	/* Create the raw data to add as a payload */
	byte* raw_payload = new byte[payload_size];
	byte* cpy_ptr = raw_payload;

	/* Iterate through each Query and write the raw data */
	for(it_query  = Queries.begin() ; it_query != Queries.end() ; it_query++) {
		/* Write data */
		size_t nwrite = (*it_query).Write(cpy_ptr);
		/* Update the pointer */
		cpy_ptr += nwrite;
	}

	for(it_ans  = Answers.begin() ; it_ans != Answers.end() ; it_ans++) {
		/* Write data */
		size_t nwrite = (*it_ans).Write(cpy_ptr);
		/* Update the pointer */
		cpy_ptr += nwrite;
	}

	for(it_auth  = Authority.begin() ; it_auth != Authority.end() ; it_auth++) {
		/* Write data */
		size_t nwrite = (*it_auth).Write(cpy_ptr);
		/* Update the pointer */
		cpy_ptr += nwrite;
	}

	for(it_add  = Additional.begin() ; it_add != Additional.end() ; it_add++) {
		/* Write data */
		size_t nwrite = (*it_add).Write(cpy_ptr);
		/* Update the pointer */
		cpy_ptr += nwrite;
	}

	/* Set the payload of the layer */
	SetPayload(raw_payload,payload_size);

	delete [] raw_payload;
}

void DNS::LibnetBuild(libnet_t* l) {
	/* Get the payload */
	size_t payload_size = GetPayloadSize();
	byte* payload;

	if (payload_size) {
		payload = new byte[payload_size];
		GetPayload(payload);
	} else
		payload = 0;

	/* Now write the data into de libnet context */
	int dns = libnet_build_dnsv4 (  LIBNET_UDP_DNSV4_H,
								    GetIdentification(),
								    GetFlags(),
								    GetTotalQuestions(),
								    GetTotalAnswer(),
								    GetTotalAuthority(),
								    GetTotalAdditional(),
								    payload,
								    payload_size,
								    l,
								    0
							      );

	/* In case of error */
	if (dns == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "DNS::LibnetBuild()",
		             "Unable to build DNS header: " + string(libnet_geterror (l)));
		exit (1);
	}

	if(payload)
		delete [] payload;

}

static void zero_buff(char* buff, size_t ndata) {
	for(size_t i = 0 ; i < ndata ; i++)
		buff[i] = 0x0;
}

void SetContainerSection(vector<DNS::DNSAnswer>& container, ns_sect section, ns_msg* handle) {
	/* Allocate memory for buffer */
	char* buff = new char[MAXDNAME];

	/* Parse the Answers */
	for(size_t i = 0 ; i < ns_msg_count(*handle,section) ; i++) {
		/* RR data structure */
		ns_rr rr;
		/* Parse the data */
		if (ns_parserr(handle,section,i,&rr) < 0) {
			PrintMessage(Crafter::PrintCodes::PrintPerror,
						 "DNS::FromRaw()",
						 "Error Parsing the Answers");
			exit(1);
		}

		/* Put zeros on the buffer */
		zero_buff(buff,MAXDNAME);

		/* Get the name associated with the answer */
        string qname = string(ns_rr_name(rr));

        /* Get the type */
        short_word qtype = ns_rr_type(rr);

        /* String for the RData */
        string rdata;

        if(qtype != DNS::TypeA) {
			/* Expand the name domain name */
			if (ns_name_uncompress(
						ns_msg_base(*handle),/* Start of the message    */
						ns_msg_end(*handle), /* End of the message      */
						ns_rr_rdata(rr),     /* Position in the message */
						buff,                /* Result                  */
						MAXDNAME)            /* Size of buffer   */
								  < 0) {
				PrintMessage(Crafter::PrintCodes::PrintPerror,
							 "DNS::FromRaw()",
							 "Error Uncompressing the RData");
				exit(1);
			}

			/* Put the data into a string */
			rdata = string(buff);

        } else {
        	/* Parse the IP address */
        	const byte* rdata_ptr = ns_rr_rdata(rr);
            struct in_addr addr;
        	/* Get the 32 bit number */
        	addr.s_addr = *((word*)(rdata_ptr));

        	/* Convert it into a IP string */
        	rdata = string(inet_ntoa(addr));
        }

	    /* Create the answer and push it into the container */
        DNS::DNSAnswer dns_answer(qname,rdata);

	    /* Set the Class */
        dns_answer.SetClass(ns_rr_class(rr));
        /* Set the type */
        dns_answer.SetType(qtype);
        /* Set the TTL */
        dns_answer.SetTTL(ns_rr_ttl(rr));

        container.push_back(dns_answer);
	}

	delete [] buff;

}

void DNS::FromRaw(const RawLayer& raw_layer) {
	/* Get size of the raw layer */
	size_t data_size = raw_layer.GetSize();

	/* Copy all the data */
	byte* data = new byte[data_size];
	raw_layer.GetData(data);

	/* Create the header */
	PutData(data);

	/* Initialize the response parser */
	ns_msg handle;
	if (ns_initparse(data,data_size,&handle) < 0) {
		PrintMessage(Crafter::PrintCodes::PrintPerror,
					 "DNS::FromRaw()",
					 "Error initializing the parsing routines");
		exit(1);
	}

	char* buff = new char[MAXDNAME];

	/* First, parse the queries... Simple */
	for(size_t i = 0 ; i < GetTotalQuestions() ; i++) {
		/* RR data structure */
		ns_rr rr;
		/* Parse the data */
		if (ns_parserr(&handle,ns_s_qd,i,&rr) < 0) {
			PrintMessage(Crafter::PrintCodes::PrintPerror,
						 "DNS::FromRaw()",
						 "Error Parsing the Queries");
			exit(1);
		}
		/* Set the Query name */
        string qname = string(ns_rr_name(rr));
        /* Create a DNS Query and push it into the container */
        DNSQuery dns_query(qname);
        /* Set the class */
        dns_query.SetClass(ns_rr_class(rr));
        /* Set the type */
        dns_query.SetType(ns_rr_type(rr));

        Queries.push_back(dns_query);
	}

	delete [] buff;

	SetContainerSection(Answers,ns_s_an,&handle);
	SetContainerSection(Authority,ns_s_ns,&handle);
	SetContainerSection(Additional,ns_s_ar,&handle);

	delete [] data;
}

void DNS::Print() const {
	cout << "< ";
	cout << name << " (" << dec << GetSize() << " bytes) " << ":: ";

	cout << "Identification = " << hex << "0x" << GetIdentification() << " ; ";

	byte qr_flag = GetQRFlag();
	cout << "QR = " << hex << (unsigned int)(qr_flag);
			if(qr_flag) cout << " (Response) ; ";
			else cout << " (Query) ; ";
	cout << "OperationCode = " << flagsOpCode[GetOpCode()] << " ; ";
	cout << "AA = " << hex << (unsigned int)(GetAAFlag()) << " ; " ;
	cout << "TC = " << hex << (unsigned int)(GetTCFlag()) << " ; " ;
	cout << "RD = " << hex << (unsigned int)(GetRDFlag()) << " ; " ;
	cout << "RA = " << hex << (unsigned int)(GetRAFlag()) << " ; " ;
	cout << "AD = " << hex << (unsigned int)(GetADFlag()) << " ; " ;
	cout << "CD = " << hex << (unsigned int)(GetCDFlag()) << " ; " ;
	cout << "ReturnCodeCode = " << flagsRCode[GetRCode()] << " ; ";

	cout << "TotalQuestions = " << GetTotalQuestions() << " ; ";
	cout << "TotalAnswer = " << GetTotalAnswer() << " ; ";
	cout << "TotalAuthority = " << GetTotalAuthority() << " ; ";
	cout << "TotalAdditional = " << GetTotalAdditional() << " ; ";

	cout << "Payload = " << endl;

	vector<DNSQuery>::const_iterator it_query;
	for(it_query  = Queries.begin() ; it_query != Queries.end() ; it_query++) {
		(*it_query).Print();cout << endl;
	}

	vector<DNSAnswer>::const_iterator it_ans;
	for(it_ans  = Answers.begin() ; it_ans != Answers.end() ; it_ans++) {
		(*it_ans).Print();cout << endl;
	}

	vector<DNSAnswer>::const_iterator it_auth;
	for(it_auth  = Authority.begin() ; it_auth != Authority.end() ; it_auth++) {
		(*it_auth).Print();cout << endl;
	}

	vector<DNSAnswer>::const_iterator it_add;
	for(it_add  = Additional.begin() ; it_add != Additional.end() ; it_add++) {
		(*it_add).Print();cout << endl;
	}

	cout << ">" << endl;
}

