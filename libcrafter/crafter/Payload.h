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


#ifndef PAYLOAD_H_
#define PAYLOAD_H_

#include <iostream>
#include <cstring>

typedef unsigned char byte;

namespace Crafter {

	class Payload {

	protected:
		/* Readable payload */
		byte IsReadable;

		/* Total size, includeng header */
		size_t size;

		/* Data stored on the Payload */
		byte* storage;

		/* Allocate more T objects */
		void inflate(int increase);

		/* Clear the Payload */
		void clear ();

	public:

		friend class Layer;

		Payload() {
			/* Clear everything */
			size = 0;
			storage = 0;

			/* By default is readable */
			IsReadable = 1;
		};

		/* Copy constructor */
		Payload(const Payload& payload) {
			/* Clear everything */
			size = 0;
			storage = 0;

			/* By default is readable */
			IsReadable = 1;

			SetPayload(payload.storage,payload.size);
		};

		/* Equal from a general Layer */
		Payload& operator=(const Payload& payload) {
			SetPayload(payload.storage,payload.size);
			return *this;
		}

		/* Get size in bytes of the payload */
		size_t GetSize() const { return size; };

		/* Set payload */
		void SetPayload (const byte *data, size_t ndata);

		/* Add more stuff to the payload */
		void AddPayload (const byte* data, size_t ndata);

		/* Set payload */
		void SetPayload (const char *data);
		void SetPayload (const Payload& payload);

		/* Add more stuff to the payload */
		void AddPayload (const char* data);
		void AddPayload (const Payload& payload);

		/* Copy the data into the pointer and returns the number of bytes copied */
		size_t GetPayload(byte* dst) const;

		/* Copy the data into the pointer (no more than ndata) and returns the number of bytes copied */
		size_t GetPayload(byte* dst, size_t ndata) const;

		/* Clear the payload */
		void Clear() { clear(); };

		/* Print characters one by one */
		void PrintChars() const;

		/* Print Payload */
		virtual void Print() const;

		virtual ~Payload() {
				if (storage)
					delete [] storage;
		};
	};

}


#endif /* PAYLOAD_H_ */
