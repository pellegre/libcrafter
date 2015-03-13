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


#ifndef BITHANDLING_H_
#define BITHANDLING_H_

#include <iostream>
#include <string>
#include <cstdio>
#include <stdint.h>

typedef uint32_t word;
typedef uint16_t short_word;
typedef uint8_t byte;

/* Functions for manipulating bits on a word */

namespace Crafter {

	/* Print to STDOUT the bits on word */
	void PrintBits (word value);

	/* Set a bit */
	word SetBit(word value, byte bit);

	/* Reset a bit */
	word ResetBit(word value, byte bit);

	/* Test a bit */
	word TestBit(word value, byte bit);

	/* Shift bits to right ntimes */
	word ShiftRight(word value, byte ntimes);

	/* Shift bits to right ntimes */
	word ShiftLeft(word value, byte ntimes);

	/* Clear range of bits (including ebit) */
	word ClearRange(word value, byte ibit, byte ebit);

	/* Clear all bits except the range specified */
	word ClearComplementRange(word value, byte ibit, byte ebit);

#ifndef htonll
	uint64_t htonll(uint64_t value);
#endif

#ifndef ntohll
	uint64_t ntohll(uint64_t value);
#endif

}

#endif /* BITHANDLING_H_ */
