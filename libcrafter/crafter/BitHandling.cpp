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

#include "BitHandling.h"

using namespace std;
using namespace Crafter;

void Crafter::PrintBits (word value) {

	size_t maxbit = sizeof(word) * 8 - 1;

	bool print_flag = false;

	for (int i = maxbit ; i >= 0 ; i--)
		if (value & (1 << i)) {
			cout << "1";
			print_flag = true;
		}
		else {
			if (print_flag)
			  cout << "0";
		}

	cout << endl;
}

word Crafter::SetBit(word value, byte bit)
{
	return value | (1 << bit);
}

word Crafter::ResetBit(word value, byte bit)
{
	return value & ( ~(1 << bit) );
}

word Crafter::TestBit(word value, byte bit)
{
	return 1&&(value & (1 << bit));
}

word Crafter::ShiftRight(word value, byte ntimes) {
	for (short_word i = 0 ; i < ntimes ; i++)
		value >>= 1;

	return value;
}

/* Shift bits to right ntimes */
word Crafter::ShiftLeft(word value, byte ntimes) {
	for (short_word i = 0 ; i < ntimes ; i++)
		value <<= 1;

	return value;
}

word Crafter::ClearRange(word value, byte ibit, byte ebit) {
	for (byte i = ibit; i <= ebit ; i++)
		value = ResetBit(value,i);

	return value;
}

word Crafter::ClearComplementRange(word value, byte ibit, byte ebit) {
	for (byte i = 0; i < ibit ; i++)
		value = ResetBit(value,i);

	for (byte i = ebit + 1; i <= 31 ; i++)
		value = ResetBit(value,i);

	return value;
}
