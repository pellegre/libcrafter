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

#include <arpa/inet.h>

#include "FieldInfo.h"

namespace Crafter {

	template <size_t size, size_t nbit>
	class BitsField : public Field<word> {

		const size_t nword;
		const size_t offset;
		const byte over_bytes;
		const byte rightMargin;
		const byte maskLow;
		const byte maskHigh;

		void PrintValue(std::ostream& str) const;

	public:
		BitsField(const std::string& name, size_t nword);

		void Write(byte* raw_data) const;

		void Read(const byte* raw_data);

		FieldInfo* Clone() const;

		virtual ~BitsField() {/* */};
	};

	template <size_t size, size_t nbit>
	class XBitsField : public BitsField<size,nbit> {
		void PrintValue(std::ostream& str) const;
	public:
		XBitsField(const std::string& name, size_t nword);

		FieldInfo* Clone() const;

		virtual ~XBitsField() {/* */};
	};

	template <size_t nbit>
	class BitFlag : public BitsField<1,nbit> {
		std::string str_true;
		std::string str_false;
		void PrintValue(std::ostream& str) const;
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
								nword(nword), offset(nword * 4 + nbit/8),
								over_bytes((nbit % 8 + (size - 1)) / 8),
								rightMargin(7 - (size - 1 + nbit) % 8),
								maskLow((1 << (8 - nbit%8)) - 1),
								maskHigh(~((1 << rightMargin) - 1))
{
	assert(size<=32);
	assert(rightMargin<8);
}

template<size_t size, size_t nbit>
void Crafter::BitsField<size,nbit>::Write(byte* raw_data) const {
	byte* data_ptr = raw_data + offset;
    /* Write values [x,y] in bit sequence B0..x.y..Bn
     * and x,y are in a word made of bytes Bx..By */
    /* Shift by the right margin to have Bx..By.. aligned on y */
    word value = htonl(human) << rightMargin;
	const byte* field_data = (const byte*)(&value);
	if (over_bytes) {
        /* Reset the previous bits of x (in case of multiple set) */
        data_ptr[0] &= ~maskLow;
        /* Apply x */
        data_ptr[0] |= field_data[3 - over_bytes];
		/* Copy intermediate bytes if any */
		for(int i = 1; i < over_bytes ; i++)
			data_ptr[i] = field_data[3 - over_bytes + i];
		/* Reset the previous bits of y */
        data_ptr[over_bytes] &= ~maskHigh;
        /* Apply y */
        data_ptr[over_bytes] |= field_data[3];
    } else {
		/* We span on a single byte, apply both masks at once */
		/* Reset the bits of the bitfield */
        data_ptr[0] &= (~maskLow | ~maskHigh);
		/* Copy its content */
        data_ptr[0] |= field_data[3];
	}
}
template<size_t size, size_t nbit>
void Crafter::BitsField<size,nbit>::Read(const byte* raw_data) {
	const byte* data_ptr = raw_data + offset;
    word value = 0;
    byte* field_data = (byte*)(&value);
    /* Read values [x,y] in bit sequence B0..x.y..Bn,
	 * and x,y must be stored in a word made of bytes By..Bx */
    field_data[3 - over_bytes] = data_ptr[0];
    /* Keep only the low order bits of the first byte */
    field_data[3 - over_bytes] &= maskLow;
	/* Copy all remaining bytes */
	for(int i = 1 ; i <= over_bytes ; i++)
		field_data[3 - over_bytes + i] = data_ptr[i];
	/* But exclude the low order bits of y */
    field_data[3] &= maskHigh;
    /* Shift back the value by the right margin */
    human = ntohl(value >> rightMargin);
}

template<size_t size, size_t nbit>
Crafter::FieldInfo* Crafter::BitsField<size,nbit>::Clone() const {
	BitsField<size,nbit>* new_ptr = new BitsField<size,nbit>(GetName(),nword);
	new_ptr->human = human;
	return new_ptr;
}

template<size_t size, size_t nbit>
void Crafter::BitsField<size,nbit>::PrintValue(std::ostream& str) const {
	str << std::dec << human;
}

/* ------- */

template<size_t size, size_t nbit>
Crafter::XBitsField<size,nbit>::XBitsField(const std::string& name, size_t nword) :
								  BitsField<size,nbit>(name,nword)
								  { /* */ }

template<size_t size, size_t nbit>
void Crafter::XBitsField<size,nbit>::PrintValue(std::ostream& str) const {
	str << "0x" << std::hex << this->human;
}

template<size_t size, size_t nbit>
Crafter::FieldInfo* Crafter::XBitsField<size,nbit>::Clone() const {
	XBitsField<size,nbit>* new_ptr = new XBitsField<size,nbit>(this->GetName(),this->GetWord());
	new_ptr->human = this->human;
	return new_ptr;
}

/* ------- */

template <size_t nbit>
Crafter::BitFlag<nbit>::BitFlag(const std::string& name, size_t nword,
		                        const std::string& str_true,const std::string& str_false) :
					            BitsField<1,nbit>(name,nword),
		                        str_true(str_true), str_false(str_false)
					            { /* */ }

template <size_t nbit>
void Crafter::BitFlag<nbit>::PrintValue(std::ostream& str) const {
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
