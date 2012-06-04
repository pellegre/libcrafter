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

#include "FieldType.h"

using namespace std;

FieldFactory FieldFactory::Factory;

static string mid_tab = "    ";

static inline void Printline(ostream& out, const string& line, size_t ident) {
	string str_ident = "";
	for(size_t i = 0 ; i < ident ; i++)
		str_ident += mid_tab;

	out << str_ident << line << endl;
}

static inline void Newline(std::ostream& out) {
	out << endl;
}

FieldType::FieldType(const string& name, const string& type, const string& value_type) :
		name(name), type(type), value_type(value_type) {/* */ }

void FieldType::PrintGet(std::ostream& out) const {
	Printline(out,value_type + "  Get" + name + "() const {",2);
	Printline(out,"return GetFieldValue<" + value_type + ">(Field" + name + ");",3);
	Printline(out,"};",2);
}

void FieldType::PrintSet(std::ostream& out) const {
	Printline(out,"void Set" + name + "(const " + value_type + "& value) {",2);
	Printline(out,"SetFieldValue(Field" + name + ",value);",3);
	Printline(out,"};",2);
}

void FieldType::ReadData(std::ifstream& in) {
	/* Read data of this particular field */
	Read(in);
	/* Read the default value */
	in >> default_value;
}

std::string FieldType::GetDefaultSetter() const {
	return "Set" + name + "(" + default_value + ");";
}

FieldType::~FieldType() { /*  */ }

