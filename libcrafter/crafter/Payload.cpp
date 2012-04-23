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

/* Allocate more T objects */
void Payload::inflate(int increase) {
	/* Check if our buffer is empty */
	if (!size) {
		storage = new byte[increase];
		size = increase;
		return;
	}

	/* Get new size */
	size_t new_size = size + increase;

	/* Allocate new memory */
	byte* new_buffer = new byte[new_size];

	/* Copy old buffer */
	for (int unsigned i = 0 ; i < size ; i++)
		new_buffer[i] = storage[i];

	/* Delete old buffer */
	delete [] storage;

	/* Asign new address */
	storage = new_buffer;
	size = new_size;
}

/* Clear the Payload */
void Payload::clear () {
	if (storage) {
		/* Set the size to zero */
		size = 0;
		delete [] storage;
		storage = 0;
		/* By default is readable */
		IsReadable = 1;
	}
}

void Payload::SetPayload (const byte *data, size_t ndata) {
	/* This overwrite all the data on the payload */
	clear();
	/* Get new space */
	inflate(ndata);
	/* Now, copy the data */
	for (size_t i = 0 ; i < ndata ; i++) {
		if ( (IsReadable) && (!isprint(data[i])) && (!iscntrl(data[i])) ) IsReadable = 0;
			storage[i] = data[i];
	}
}

/* Add more stuff to the payload */
void Payload::AddPayload (const byte* data, size_t ndata) {
	/* Get old size */
	size_t old_size = size;
	/* Add more space */
	inflate(ndata);
	/* Now, copy the data */
	for (size_t i = 0 ; i < ndata ; i++) {
		if ( (IsReadable) && (!isprint(data[i])) && (!iscntrl(data[i])) ) IsReadable = 0;
			storage[old_size + i] = data[i];
	}
}

/* Set payload */
void Payload::SetPayload (const char *data) {
	/* This overwrite all the data on the payload */
	clear();
	/* Get new space */
	size_t ndata = strlen(data);
	inflate(ndata);
	/* Now, copy the data */
	strncpy((char *)storage,data,ndata);
}

/* Add more stuff to the payload */
void Payload::AddPayload (const char* data) {
	/* Add more space */
	size_t ndata = strlen(data);
	inflate(ndata);
	/* Now, copy the data */
	strncat((char *)storage,data,ndata);
}

void Payload::AddPayload (const Payload& payload) {
	AddPayload(payload.storage,payload.GetSize());
}

void Payload::SetPayload (const Payload& payload) {
	SetPayload(payload.storage,payload.GetSize());
}

/* Copy the data into the pointer and returns the number of bytes copied */
size_t Payload::GetPayload(byte* dst) const {
	for (size_t i = 0 ; i < size ; i++)
		dst[i] = storage[i];

	return size;
}

size_t Payload::GetPayload(byte* dst, size_t ndata) const {
	size_t i = 0;
	for (; i < size && i < ndata; i++)
		dst[i] = storage[i];

	return i;
}

/* Print Payload */
void Payload::Print() const{
	/* Print raw data in hexadecimal format */
	if (IsReadable) {

		for(size_t i = 0 ; i < size ; i++) {
			if ((unsigned int)storage[i] == 0x09)
				std::cout << "\\t";
			else if ((unsigned int)storage[i] == 0x0d)
				std::cout << "\\r";
			else if ((unsigned int)storage[i] == 0x0a)
				std::cout << "\\n";
			else if((unsigned int)storage[i] < 0x20) {
				std::cout << "\\x";
				std::cout << std::hex << (unsigned int)storage[i];
			} else
				std::cout << storage[i];
		}

	} else {

		for(size_t i = 0 ; i < size ; i++) {
			std::cout << "\\x";
			std::cout << std::hex << (unsigned int)storage[i];
		}

	}

}

void Payload::RawString() const {
	/* Print raw data in hexadecimal format */
	for(size_t i = 0 ; i < size ; i++) {
		std::cout << "\\x";
		std::cout << std::hex << (unsigned int)((byte *)storage)[i];
	}
}

void Payload::PrintChars() const {
	for(size_t i = 0 ; i < size ; i++)
		std::cout << (char)storage[i];
}

