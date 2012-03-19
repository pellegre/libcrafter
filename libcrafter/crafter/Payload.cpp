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

void Payload::PrintChars() const {
	for(size_t i = 0 ; i < size ; i++)
		std::cout << (char)storage[i];
}

