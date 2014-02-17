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

#ifndef BYTESFIELD_H_
#define BYTESFIELD_H_

#include <iostream>
#include <iomanip>
#include <ostream>
#include <vector>

#include "FieldInfo.h"

namespace Crafter {

	template <size_t size>
	class BytesField : public Field<std::vector<byte> > {

		size_t nword;
		size_t nbyte;
		size_t offset;

	protected:

		void PrintValue(std::ostream& str) const;

	public:
		BytesField(const std::string& name, size_t nword, size_t nbyte);

		void Write(byte* raw_data) const;

		void Read(const byte* raw_data);

		FieldInfo* Clone() const;

		virtual ~BytesField() {/* */};
	};

}


template<size_t size>
Crafter::BytesField<size>::BytesField(const std::string& name, size_t nword, size_t nbyte) :
							Field<std::vector<byte> > (name,nword,nbyte*8,8*size),
							nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
	human.reserve(size);
	human.resize(size);
}

template<size_t size>
void Crafter::BytesField<size>::Write(byte* raw_data) const {
	memset(raw_data + offset,0,size * sizeof(byte));
	for(size_t i = 0 ; i < size && i < human.size() ; i++)
		raw_data[offset + i] = human[i];
}

template<size_t size>
void Crafter::BytesField<size>::Read(const byte* raw_data) {
	human.reserve(size);
	human.resize(size);
	for(size_t i = 0 ; i < size ; i++)
		 human[i] = raw_data[offset + i];
}

template<size_t size>
Crafter::FieldInfo* Crafter::BytesField<size>::Clone() const {
	BytesField<size>* new_ptr = new BytesField<size>(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

template<size_t size>
void Crafter::BytesField<size>::PrintValue(std::ostream& str) const {
	for(size_t i = 0 ; i < size && i < human.size() ; i++)
		str << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)human[i];
}

#endif /* BYTESFIELD_H_ */
