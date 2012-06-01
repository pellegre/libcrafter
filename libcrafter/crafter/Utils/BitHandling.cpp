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
