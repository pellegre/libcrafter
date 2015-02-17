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
								nword(nword) {
	assert(size<=32);
	offset = nword * 4 + nbit/8;
}

template<size_t size, size_t nbit>
void Crafter::BitsField<size,nbit>::Write(byte* raw_data) const {
    /* Number of bytes on which this field spans */
	const byte over_bytes = (nbit % 8 + (size - 1)) / 8;
    byte* data_ptr = raw_data + offset;

    /* Write values [x,y] in bit sequence B0..x.y..Bn
     * where x in B1 and y in Bn
     * and x,y are in a word made of bytes By..Bx */
    /* Shift by the distance y..Bn to have ..By..Bx reflect the alignment */
    const size_t y_bn_dist = 7 - (size + nbit - 1) % 8;
    uint64_t value = human << y_bn_dist;
    const byte* field_data = (const byte*)(&value);
    /* We want to store only the lower end of Bx
     * thus the rightmost part of B1 */
    byte maskLow = ( 1 << (8 - nbit%8) ) - 1 ;
    if (over_bytes) {
        /* Reset the previous bits of x (in case of multiple set) */
        data_ptr[0] &= ~maskLow;
        /* Apply x */
        data_ptr[0] |= (field_data[over_bytes] & maskLow);
    }
    /* Copy intermediate bytes*/
    size_t nbits = 8;
    for(int i = 1 ; i < over_bytes ; i++) {
        data_ptr[i] = field_data[over_bytes - i];
        nbits += 8;
    }
    /* We want to store only the higher end of By
     * thus the leftmost part of Bn-1 */
    byte maskHigh = ( 1 << y_bn_dist ) - 1 ;
    if (over_bytes) {
        /* Reset the previous bits of y */
        data_ptr[over_bytes] &= maskHigh;
        /* Apply y if we spawn on multiple bytes, or both mask at once */
        data_ptr[over_bytes] |= (field_data[0] & ~maskHigh);
    } else { /* Only a single byte, apply both masks at once */
        data_ptr[0] &= (~maskLow | maskHigh);
        data_ptr[0] |= ((field_data[0] & maskLow) & ~maskHigh);
	}
}

template<size_t size, size_t nbit>
void Crafter::BitsField<size,nbit>::Read(const byte* raw_data) {

    const byte over_bytes = (nbit % 8 + (size - 1)) / 8;
	const byte* data_ptr = raw_data + offset;

    word value = 0;
    byte* field_data = (byte*)(&value);
    /* Read values [x,y] in bit sequence B0..x.y..Bn,
     * where x in B1 and y in Bn-1*/

    /* Compute the distance between y and the start of Bn-1 */
    const size_t y_bn_dist = 7 - (size + nbit - 1) % 8;
    /* Copy B1 as it is the starting byte */
    field_data[over_bytes] |= data_ptr[0];
    /* But exclude the high order bits in [B0, x[ */
    byte maskLow = ( 1 << (8 - nbit%8) ) - 1 ;
    field_data[over_bytes] &= maskLow;
    /* Then copy all intermediate bytes */
    size_t nbits = 8;
    for(int i = 1 ; i < over_bytes ; i++) {
        field_data[over_bytes - i] = data_ptr[i];
        nbits += 8;
    }
    /* Copy Bn-1 as it contains y iff we span on more than one byte */
    if (over_bytes)
        field_data[0] |= data_ptr[over_bytes];
    /* But exclude the low order bytes not part of y in ]y, Bn] */
    byte maskHigh = ( 1 << y_bn_dist ) - 1 ;
    field_data[0] &= ~maskHigh;
    /* Shift back the value by the distance between y and the start of Bn-1 */
    value = value >> y_bn_dist;
    human = value;
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
