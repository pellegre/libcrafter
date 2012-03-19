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

}

#endif /* BITHANDLING_H_ */
