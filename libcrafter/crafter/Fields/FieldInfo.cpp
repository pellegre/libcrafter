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

#include "FieldInfo.h"

using namespace std;

Crafter::FieldInfo::FieldInfo(const std::string& name, word nword, word bitpos, word length) :
	name(name), nword(nword), bitpos(bitpos), length(length), field_set(0) {

	if(bitpos > 31)
		cerr << "[@] ERROR on FieldInfo: bitpos = " << bitpos << " ; name = " << name << endl;
}

void Crafter::FieldInfo::PrintDebug() const {
	cout << endl;
	cout << "name = "      << dec << name            << " ";
	cout << "nword = "     << dec << nword           << " ";
	cout << "bitpos = "    << dec << bitpos          << " ";
	cout << "length = "    << dec << length          << " ";
	cout << "field_set = " << dec << (word)field_set << endl;
}

Crafter::FieldInfo* Crafter::FieldInfo::CloneField() const {
	FieldInfo* ptr = Clone();
	ptr->field_set = field_set;
	return ptr;
}

namespace Crafter {

	ostream& operator<<(ostream& str, Crafter::FieldInfo const& data) {
		data.Print(str);
		return str;
	}

}
