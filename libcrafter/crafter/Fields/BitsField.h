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

#ifndef BITSFIELD_H_
#define BITSFIELD_H_

#include <iostream>
#include <iomanip>
#include <ostream>
#include <bitset>
#include <cassert>

#include "FieldInfo.h"

namespace Crafter {

	template <size_t size, size_t nbit>
	class BitsField : public Field<word> {

		size_t nword;
		size_t offset;
		template<size_t psize, size_t bitp>
		struct ByteBitPack {
			static const int pad = (8>=(psize + bitp)) ? (8 - (psize + bitp)) : (8 - bitp);
			word : pad ;
			word fieldm:psize;
			word : bitp;
		};

		template<size_t psize>
		struct WordBitPack {
			word fieldm:psize;
			word : (32 - psize);
		};

		void Print(std::ostream& str) const;

	public:
		BitsField(const std::string& name, size_t nword);

		void Write(byte* raw_data) const;

		void Read(const byte* raw_data);

		FieldInfo* Clone() const;

		virtual ~BitsField() {/* */};
	};

	template <size_t size, size_t nbit>
	class XBitsField : public BitsField<size,nbit> {
		void Print(std::ostream& str) const;
	public:
		XBitsField(const std::string& name, size_t nword);

		FieldInfo* Clone() const;

		virtual ~XBitsField() {/* */};
	};

	template <size_t nbit>
	class TCPFlags : public BitsField<9,nbit> {
		static const std::string flags[];
		void Print(std::ostream& str) const;
	public:
		TCPFlags(const std::string& name, size_t nword);

		FieldInfo* Clone() const;

		virtual ~TCPFlags();
	};

	template <size_t nbit>
	class BitFlag : public BitsField<1,nbit> {
		std::string str_true;
		std::string str_false;
		void Print(std::ostream& str) const;
	public:
		BitFlag(const std::string& name, size_t nword, const std::string& str_true,const std::string& str_false);

		FieldInfo* Clone() const;

		virtual ~BitFlag();
	};

}

/* ------- */

template<size_t size, size_t nbit>
Crafter::BitsField<size,nbit>::BitsField(const std::string& name, size_t nword) :
								Field<word>(name,nword,nbit,size),
								nword(nword) {
	assert(size<=32);
	offset = nword * 4 + nbit/8;
}

template<size_t size, size_t nbit>
void Crafter::BitsField<size,nbit>::Write(byte* raw_data) const {
	const byte over_bytes = ((nbit%8 + size)-1)/8;
	const byte* bytes_ptr = (const byte *)&human;
	byte* data_ptr = raw_data + offset;

	if (over_bytes == 0) {

		ByteBitPack<size,nbit%8>* ptr = reinterpret_cast<ByteBitPack<size,nbit%8>*> (data_ptr);
		ptr->fieldm = bytes_ptr[0];

	} else if (over_bytes == 1) {

		WordBitPack<size> FieldValue;
		memset((void*)&FieldValue,0,sizeof(WordBitPack<size>));
		FieldValue.fieldm = human;
		const byte* field_data = reinterpret_cast<const byte*>(&FieldValue);
		byte mask = ( 1 << size%8 ) - 1 ;
		data_ptr[0] &= ~mask;
		data_ptr[0] |= field_data[over_bytes];
		size_t nbits = 8;
		byte maskHigh = ( 1 << (size - (nbits - nbit%8)) ) - 1 ;
		data_ptr[over_bytes] &= maskHigh;
		data_ptr[over_bytes] |= field_data[0];

	} else {

		uint64_t value = human;
		value = value << ((over_bytes + 1)*8 - size);
		const byte* field_data = (const byte*)(&value);
		byte maskLow = ( 1 << (8 - nbit%8) ) - 1 ;
		data_ptr[0] &= ~maskLow;
		data_ptr[0] |= field_data[over_bytes];

		size_t nbits = 8;
		for(int i = 1 ; i < over_bytes ; i++) {
			data_ptr[i] = field_data[over_bytes - i];
			nbits += 8;
		}

		byte maskHigh = ( 1 << (size - (nbits - nbit%8)) ) - 1 ;

		data_ptr[over_bytes] &= maskHigh;
		data_ptr[over_bytes] |= field_data[0];

	}
}

template<size_t size, size_t nbit>
void Crafter::BitsField<size,nbit>::Read(const byte* raw_data) {
	const byte over_bytes = ((nbit%8 + size)-1)/8;
	const byte* data_ptr = raw_data + offset;

	if (over_bytes == 0) {

		const ByteBitPack<size,nbit%8>* ptr = reinterpret_cast<const ByteBitPack<size,nbit%8>*> (data_ptr);
		human = ptr->fieldm;

	} else if (over_bytes == 1) {

		WordBitPack<size> FieldValue;
		memset((void*)&FieldValue,0,sizeof(WordBitPack<size>));
		byte* field_data = reinterpret_cast<byte*>(&FieldValue);
		byte mask = ( 1 << size%8 ) - 1 ;
		field_data[1] &= ~mask;
		field_data[1] |= data_ptr[0];
		size_t nbits = 8;
		byte maskHigh = ( 1 << (size - (nbits - nbit%8)) ) - 1 ;
		field_data[0] &= maskHigh;
		field_data[0] |= data_ptr[1];
		human = FieldValue.fieldm ;

	} else {

		word value = 0;
		byte* field_data = (byte*)(&value);
		byte maskLow = ( 1 << size%8 ) - 1 ;
		field_data[over_bytes] &= ~maskLow;
		field_data[over_bytes] |= data_ptr[0];

		size_t nbits = 8;
		for(int i = 1 ; i < over_bytes ; i++) {
			field_data[over_bytes - i] = data_ptr[i];
			nbits += 8;
		}

		byte maskHigh = ( 1 << (size - (nbits - nbit%8)) ) - 1 ;

		field_data[0] &= maskHigh;
		field_data[0] |= data_ptr[over_bytes];

		value = value >> ((over_bytes + 1)*8 - size);
		human = value;

	}
}

template<size_t size, size_t nbit>
Crafter::FieldInfo* Crafter::BitsField<size,nbit>::Clone() const {
	BitsField<size,nbit>* new_ptr = new BitsField<size,nbit>(GetName(),nword);
	new_ptr->human = human;
	return new_ptr;
}

template<size_t size, size_t nbit>
void Crafter::BitsField<size,nbit>::Print(std::ostream& str) const {
	str << GetName() << " = " << std::dec << human;
}

/* ------- */

template<size_t size, size_t nbit>
Crafter::XBitsField<size,nbit>::XBitsField(const std::string& name, size_t nword) :
								  BitsField<size,nbit>(name,nword)
								  { /* */ }

template<size_t size, size_t nbit>
void Crafter::XBitsField<size,nbit>::Print(std::ostream& str) const {
	str << this->GetName() << " = 0x" << std::hex << this->human;
}

template<size_t size, size_t nbit>
Crafter::FieldInfo* Crafter::XBitsField<size,nbit>::Clone() const {
	XBitsField<size,nbit>* new_ptr = new XBitsField<size,nbit>(this->GetName(),this->GetWord());
	new_ptr->human = this->human;
	return new_ptr;
}

/* ------- */

/* Control flags names */
template <size_t nbit>
const std::string Crafter::TCPFlags<nbit>::flags[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS"};

template <size_t nbit>
Crafter::TCPFlags<nbit>::TCPFlags(const std::string& name, size_t nword) :
					     BitsField<9,nbit>(name,nword)
                         { /* */ }

template <size_t nbit>
void Crafter::TCPFlags<nbit>::Print(std::ostream& str) const {
	str << this->GetName() << " = ";

	str << "( ";

	for(int i = 0 ; i < 9 ; i++) {
		int flag_shift = 1 << i;

		if (flag_shift & this->human)
			str << flags[i] << " ";
	}

	str << ")";
}

template <size_t nbit>
Crafter::FieldInfo* Crafter::TCPFlags<nbit>::Clone() const {
	TCPFlags<nbit>* new_ptr = new TCPFlags<nbit>(this->GetName(),this->GetWord());
	new_ptr->human = this->human;
	return new_ptr;
}

template <size_t nbit>
Crafter::TCPFlags<nbit>::~TCPFlags() { /* */ }

/* ------- */

template <size_t nbit>
Crafter::BitFlag<nbit>::BitFlag(const std::string& name, size_t nword,
		                        const std::string& str_true,const std::string& str_false) :
					            BitsField<1,nbit>(name,nword),
		                        str_true(str_true), str_false(str_false)
					            { /* */ }

template <size_t nbit>
void Crafter::BitFlag<nbit>::Print(std::ostream& str) const {
	str << this->GetName() << " = ";
	if(this->human)
		str << "1 (" << str_true << ")";
	else
		str << "0 (" << str_false << ")";
}

template <size_t nbit>
Crafter::FieldInfo* Crafter::BitFlag<nbit>::Clone() const {
	BitFlag<nbit>* new_ptr = new BitFlag<nbit>(this->GetName(),this->GetWord(),str_true,str_false);
	new_ptr->human = this->human;
	return new_ptr;
}

template <size_t nbit>
Crafter::BitFlag<nbit>::~BitFlag() { /* */ }

#endif /* BITSFIELD_H_ */
