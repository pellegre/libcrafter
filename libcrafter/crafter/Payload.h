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


#ifndef PAYLOAD_H_
#define PAYLOAD_H_

#include <iostream>
#include <vector>
#include <string>
#include <cstring>

#include "Types.h"

namespace Crafter {

	class Payload {

	protected:
		/* Readable payload */
		byte IsReadable;

		/* Container of data */
		std::vector<byte> storage;

		/* Clear the Payload */
		void clear () { storage.clear(); };

		/* Initial reserved size */
		static const size_t reserved = 128;

	public:

		Payload() : IsReadable(1) {
			/* Reserve */
			storage.reserve(reserved);
		};

		/* Copy constructor */
		Payload(const Payload& payload) : IsReadable(payload.IsReadable), storage(payload.storage) { };

		Payload(const std::vector<byte>& raw_data) : IsReadable(1) {
			storage.reserve(reserved);
			SetPayload(&raw_data[0],raw_data.size());
		};

		/* Equal from a general Layer */
		Payload& operator=(const Payload& payload) {
			storage = payload.storage;
			IsReadable = payload.IsReadable;
			return *this;
		}

		/* Get size in bytes of the payload */
		size_t GetSize() const { return storage.size(); };

		/* Set payload */
		void SetPayload (const char *data);
		void SetPayload (const Payload& payload);
		void SetPayload (const byte *data, size_t ndata);

		/* Add more stuff to the payload */
		void AddPayload (const char* data);
		void AddPayload (const Payload& payload);
		void AddPayload (const byte* data, size_t ndata);

		/* Copy the data into the pointer and returns the number of bytes copied */
		size_t GetPayload(byte* dst) const;

		/* Copy the data into the pointer (no more than ndata) and returns the number of bytes copied */
		size_t GetPayload(byte* dst, size_t ndata) const;

		/* Get payload as a STL string */
		std::string GetString() const;

		/* Clear the payload */
		void Clear() { storage.clear(); };

		/* Print characters one by one */
		void PrintChars(std::ostream& str = std::cout) const;

		/* Print a raw string of the payload */
		void RawString(std::ostream& str = std::cout) const;

		/* Print Payload */
		virtual void Print(std::ostream& str = std::cout) const;

		/* Return a constant reference to the container */
		const std::vector<byte>& GetContainer() const { return storage; };

		/* Get raw pointer */
		const byte* GetRawPointer() const { return (const byte*)&storage[0]; };

		virtual ~Payload() { /* */ };
	};

}


#endif /* PAYLOAD_H_ */
