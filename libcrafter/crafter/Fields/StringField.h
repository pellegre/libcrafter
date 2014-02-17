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

#ifndef STRINGFIELD_H_
#define STRINGFIELD_H_

#include <iostream>
#include <ostream>
#include <string>
#include "FieldInfo.h"

namespace Crafter {

	template<size_t size>
	class StringField : public Field<std::string> {

		size_t nword;
		size_t nbyte;
		size_t offset;

		void PrintValue(std::ostream& str) const;

	public:

		StringField(const std::string& name, size_t nword, size_t nbyte);

		void Write(byte* raw_data) const;

		void Read(const byte* raw_data);

		FieldInfo* Clone() const;

		virtual ~StringField() {/* */};
	};

}

template<size_t size>
Crafter::StringField<size>::StringField(const std::string& name, size_t nword, size_t nbyte) :
							Field<std::string> (name,nword,nbyte*8,8*size),
							nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

template<size_t size>
void Crafter::StringField<size>::Write(byte* raw_data) const {
	memset(raw_data + offset,0,size * sizeof(byte));
	for(size_t i = 0 ; i < size && i < human.size() ; i++)
		raw_data[offset + i] = human[i];
}

template<size_t size>
void Crafter::StringField<size>::Read(const byte* raw_data) {
	human = std::string((const char*)(raw_data + offset),size);
}

template<size_t size>
Crafter::FieldInfo* Crafter::StringField<size>::Clone() const {
	StringField<size>* new_ptr = new StringField<size>(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

template<size_t size>
void Crafter::StringField<size>::PrintValue(std::ostream& str) const {
	str << human;
}

#endif /* STRINGFIELD_H_ */
