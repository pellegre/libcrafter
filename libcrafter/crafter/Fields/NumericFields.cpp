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

#include "NumericFields.h"
#include "../Utils/BitHandling.h"

#include <arpa/inet.h>
#include <netinet/in.h>

using namespace std;
using namespace Crafter;

ByteField::ByteField(const std::string& name, size_t nword, size_t nbyte) :
		             Field<byte> (name,nword,nbyte*8,8),
                     nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

void ByteField::PrintValue(std::ostream& str) const {
	str << dec << (word)human;
}

FieldInfo* ByteField::Clone() const {
	ByteField* new_ptr = new ByteField(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

void ByteField::Write(byte* raw_data) const {
	raw_data[offset] = human;
}

void ByteField::Read(const byte* raw_data){
	human = raw_data[offset];
}

ByteField::~ByteField() { /* */ }

XByteField::XByteField(const std::string& name, size_t nword, size_t nbyte) :
		               ByteField(name,nword,nbyte)
                       { /* */ }

void XByteField::PrintValue(std::ostream& str) const {
	str << "0x" << hex << (word)human;
}

FieldInfo* XByteField::Clone() const {
	XByteField* new_ptr = new XByteField(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

XByteField::~XByteField() { /* */ }

/* Control flags names */
const std::string TCPFlags::flags[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};

TCPFlags::TCPFlags(const std::string& name, size_t nword, size_t nbyte) :
		               ByteField(name,nword,nbyte)
                       { /* */ }

void TCPFlags::PrintValue(std::ostream& str) const {
	str << "( ";

	for(int i = 0 ; i < 8 ; i++) {
		int flag_shift = 1 << i;

		if (flag_shift & human)
			str << flags[i] << " ";
	}

	str << ")";
}

FieldInfo* TCPFlags::Clone() const {
	TCPFlags* new_ptr = new TCPFlags(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

TCPFlags::~TCPFlags() { /* */ }

ShortField::ShortField(const std::string& name, size_t nword, size_t nbyte) :
		             Field<short_word> (name,nword,nbyte*8,16),
                     nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

void ShortField::PrintValue(std::ostream& str) const {
	str << dec << (word)human;
}

FieldInfo* ShortField::Clone() const {
	ShortField* new_ptr = new ShortField(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

void ShortField::Write(byte* raw_data) const {
	short_word* ptr = (short_word*)(raw_data + offset);
	*ptr = htons(human);
}

void ShortField::Read(const byte* raw_data){
	short_word* ptr = (short_word*)(raw_data + offset);
	human = ntohs(*ptr);
}

ShortField::~ShortField() { /* */ }

ShortHostField::ShortHostField(const std::string& name, size_t nword, size_t nbyte) :
		             Field<short_word> (name,nword,nbyte*8,16),
                     nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

void ShortHostField::PrintValue(std::ostream& str) const {
	str << dec << (word)human;
}

FieldInfo* ShortHostField::Clone() const {
	ShortHostField* new_ptr = new ShortHostField(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

void ShortHostField::Write(byte* raw_data) const {
	short_word* ptr = (short_word*)(raw_data + offset);
	*ptr = human;
}

void ShortHostField::Read(const byte* raw_data){
	short_word* ptr = (short_word*)(raw_data + offset);
	human = *ptr;
}

ShortHostField::~ShortHostField() { /* */ }

ShortHostNetField::ShortHostNetField(const std::string& name, size_t nword, size_t nbyte) :
									ShortHostField(name,nword,nbyte)
                         { /* */ }

void ShortHostNetField::Read(const byte* raw_data){
	short_word* ptr = (short_word*)(raw_data + offset);
	human = ntohs(*ptr);
}

FieldInfo* ShortHostNetField::Clone() const {
	ShortHostNetField* new_ptr = new ShortHostNetField(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

ShortHostNetField::~ShortHostNetField() { /* */ }

XShortField::XShortField(const std::string& name, size_t nword, size_t nbyte) :
						 ShortField(name,nword,nbyte)
                         { /* */ }

void XShortField::PrintValue(std::ostream& str) const {
	str << "0x" << hex << (word)human;
}

FieldInfo* XShortField::Clone() const {
	XShortField* new_ptr = new XShortField(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

XShortField::~XShortField() { /* */ }

WordField::WordField(const std::string& name, size_t nword, size_t nbyte) :
		             Field<word> (name,nword,nbyte*8,32),
                     nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

void WordField::PrintValue(std::ostream& str) const {
	str << dec << (word)human;
}

FieldInfo* WordField::Clone() const {
	WordField* new_ptr = new WordField(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

void WordField::Write(byte* raw_data) const {
	word* ptr = (word*)(raw_data + offset);
	*ptr = htonl(human);
}

void WordField::Read(const byte* raw_data){
	word* ptr = (word*)(raw_data + offset);
	human = ntohl(*ptr);
}

WordField::~WordField() { /* */ }

WordHostField::WordHostField(const std::string& name, size_t nword, size_t nbyte) :
		             Field<word> (name,nword,nbyte*8,32),
                     nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

void WordHostField::PrintValue(std::ostream& str) const {
	str << dec << (word)human;
}

FieldInfo* WordHostField::Clone() const {
	WordHostField* new_ptr = new WordHostField(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

void WordHostField::Write(byte* raw_data) const {
	word* ptr = (word*)(raw_data + offset);
	*ptr = human;
}

void WordHostField::Read(const byte* raw_data){
	word* ptr = (word*)(raw_data + offset);
	human = *ptr;
}

WordHostField::~WordHostField() { /* */ }

XWordField::XWordField(const std::string& name, size_t nword, size_t nbyte) :
						 WordField(name,nword,nbyte)
                         { /* */ }

void XWordField::PrintValue(std::ostream& str) const {
	str << "0x" << hex << (word)human;
}

FieldInfo* XWordField::Clone() const {
	XWordField* new_ptr = new XWordField(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

XWordField::~XWordField() { /* */ }

Int64Field::Int64Field(const std::string& name, size_t nword, size_t nbyte) :
						Field<uint64_t> (name,nword,nbyte*8,64),
						nword(nword), nbyte(nbyte) {
	offset = nword * 4 + nbyte;
}

void Int64Field::PrintValue(std::ostream& str) const {
	str << GetName() << " = " << dec << (uint64_t)human;
}

FieldInfo* Int64Field::Clone() const {
	Int64Field* new_ptr = new Int64Field(GetName(),nword,nbyte);
	new_ptr->human = human;
	return new_ptr;
}

void Int64Field::Write(byte* raw_data) const {
	uint64_t* ptr = (uint64_t*)(raw_data + offset);
	*ptr = htonll(human);
}

void Int64Field::Read(const byte* raw_data){
	word* ptr = (word*)(raw_data + offset);
	human = ntohll(*ptr);
}

Int64Field::~Int64Field() { /* */ }
