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

#include "Payload.h"

using namespace std;
using namespace Crafter;

void Payload::SetPayload (const byte *data, size_t ndata) {
	storage.clear();
	AddPayload(data,ndata);
}

/* Add more stuff to the payload */
void Payload::AddPayload (const byte* data, size_t ndata) {
	/* Now, copy the data */
	for (size_t i = 0 ; i < ndata ; i++) {
		if ( (IsReadable) && (!isprint(data[i])) && (!iscntrl(data[i])) ) IsReadable = 0;
			storage.push_back(data[i]);
	}
}

/* Set payload */
void Payload::SetPayload (const char *data) {
	size_t ndata = strlen(data);
	storage = vector<byte>(data, data + ndata);
}

/* Add more stuff to the payload */
void Payload::AddPayload (const char* data) {
	size_t ndata = strlen(data);
	for (size_t i = 0 ; i < ndata ; i++)
		storage.push_back(data[i]);
}

void Payload::SetPayload (const Payload& payload) {
	storage = payload.storage;
}

void Payload::AddPayload (const Payload& payload) {
	for (size_t i = 0 ; i < payload.storage.size() ; i++) {
		if ( (IsReadable) && (!isprint(payload.storage[i])) && (!iscntrl(payload.storage[i])) ) IsReadable = 0;
			storage.push_back(payload.storage[i]);
	}}

/* Copy the data into the pointer and returns the number of bytes copied */
size_t Payload::GetPayload(byte* dst) const {
	size_t size = GetSize();
	for (size_t i = 0 ; i < size ; i++)
		dst[i] = storage[i];

	return size;
}

size_t Payload::GetPayload(byte* dst, size_t ndata) const {
	size_t i = 0;
	size_t size = GetSize();
	for (; i < size && i < ndata; i++)
		dst[i] = storage[i];

	return i;
}

string Payload::GetString() const {
	return string(storage.begin(),storage.end());
}

/* Print Payload */
void Payload::Print(ostream& str) const{
	size_t size = GetSize();

	/* Print raw data in hexadecimal format */
	if (IsReadable) {

		for(size_t i = 0 ; i < size ; i++) {
			if ((unsigned int)storage[i] == 0x09)
				str << "\\t";
			else if ((unsigned int)storage[i] == 0x0d)
				str  << "\\r";
			else if ((unsigned int)storage[i] == 0x0a)
				str  << "\\n";
			else if((unsigned int)storage[i] < 0x20) {
				str  << "\\x";
				str  << std::hex << (unsigned int)storage[i];
			} else
				str  << storage[i];
		}

	} else {

		for(size_t i = 0 ; i < size ; i++) {
			str  << "\\x";
			str  << std::hex << (unsigned int)storage[i];
		}

	}

}

void Payload::RawString(ostream& str) const {
	size_t size = GetSize();

	/* Print raw data in hexadecimal format */
	for(size_t i = 0 ; i < size ; i++) {
		str  << "\\x";
		str  << std::hex << (unsigned int)(storage)[i];
	}
}

void Payload::PrintChars(ostream& str) const {
	size_t size = GetSize();

	for(size_t i = 0 ; i < size ; i++)
		str  << (char)storage[i];
}

