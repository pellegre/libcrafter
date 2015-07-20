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

#include "Proto.h"

using namespace std;

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

std::string toUpper(std::string uperName) {
	for_each(uperName.begin(), uperName.end(), convert());
	return uperName;
}

Proto::Proto(const string& name, const string& id) : protoName(name) , protoID(id) { /* */ }

void Proto::PrintHdr() const {
	string out_file(protoName+".h");

	ofstream out(out_file.c_str());

	/* Print license */
	if(PrintLicense(out,"../../LICENSE"))
		if(PrintLicense(out,"ProtoSource/LICENSE"))
			if(PrintLicense(out,"../LICENSE"))
				cerr << "[@] Unable to open the license file when writing header. " << endl;

	/* Copy to put the name uppercase */
	string uperName = toUpper(protoName);

	Printline(out,"#ifndef " + uperName + "_H_",0);
	Printline(out,"#define " + uperName + "_H_",0);
	Newline(out);

	Printline(out,"#include \"../Layer.h\"",0);
	Newline(out);
	Printline(out,"namespace Crafter {",0);
	Newline(out);
	Printline(out,"class " + protoName +  ": public Layer {",1);
	Newline(out);

	/* Private functions */

	Printline(out,"void DefineProtocol();",2);
	Newline(out);

	Printline(out,"Constructor GetConstructor() const {",2);
	Printline(out,"return " + protoName +  "::" + protoName +  "ConstFunc;",3);
	Printline(out,"};",2);
	Newline(out);

	Printline(out,"static Layer* " + protoName +  "ConstFunc() {",2);
	Printline(out,"return new " + protoName + ";",3);
	Printline(out,"};",2);
	Newline(out);

	Printline(out,"void Craft();",2);
	Newline(out);

	Printline(out,"std::string MatchFilter() const ;",2);
	Newline(out);

	Printline(out,"void ReDefineActiveFields();",2);
	Newline(out);

	Printline(out,"void ParseLayerData(ParseInfo* info);",2);
	Newline(out);

	/* Iterator over each field */
	const_iterator it_field;
	/* Print the fields on the correct order and reference */
	size_t i = 0;
	for(it_field = begin() ; it_field != end() ; ++it_field) {
		Printline(out,"static const byte Field" + (*it_field)->GetName() + " = " + toString(i) + ";",2);
		++i;
	}
	Newline(out);

	/* Public interface functions */

	Printline(out,"public:",1);
	Newline(out);

	Printline(out,"enum { PROTO = " + toString(protoID) + "; }",2);
	Newline(out);

	Printline(out,"" + protoName +  "();",2);
	Newline(out);

	/* Print field setters */
	for(it_field = begin() ; it_field != end() ; ++it_field) {
		(*it_field)->PrintSet(out);
		Newline(out);
	}

	/* Print field getters */
	for(it_field = begin() ; it_field != end() ; ++it_field) {
		(*it_field)->PrintGet(out);
		Newline(out);
	}

	Printline(out,"~" + protoName +  "() { /* Destructor */ };",2);
	Newline(out);

	Printline(out,"};",1);
	Newline(out);
	Printline(out,"}",0);

	Newline(out);
	Printline(out,"#endif /* " + uperName + "_H_ */",0);

}

void Proto::PrintConstructorCpp(ostream& out) const {
	/* Copy to put the name uppercase */

	Printline(out,"#include \"" + protoName + ".h\"",0);
	Newline(out);
	Printline(out,"using namespace Crafter;",0);
	Printline(out,"using namespace std;",0);
	Newline(out);

	/* Constructor */
	Printline(out,protoName + "::" + protoName + "() {",0);
	Newline(out);
	Printline(out,"allocate_bytes(" + toString(protoSize) + ");",1);
	Printline(out,"SetName(\"" + protoName + "\");",1);
	Printline(out,"SetprotoID(" + protoID + ");",1);
	Printline(out,"DefineProtocol();",1);

	Newline(out);

	/* Print a line for each field that set the default value */
	const_iterator it_field;
	/* Print the fields on the correct order and reference */
	for(it_field = begin() ; it_field != end() ; ++it_field)
		Printline(out,(*it_field)->GetDefaultSetter(),1);

	Newline(out);

	Printline(out,"ResetFields();",1);
	Newline(out);

	Printline(out,"}",0);
	Newline(out);

	/* Define protocol function */
	Printline(out,"void " + protoName + "::DefineProtocol() {",0);

	for(it_field = begin() ; it_field != end() ; ++it_field)
		Printline(out,"Fields.push_back(" + (*it_field)->ReturnDefinition() + ");",1);

	Printline(out,"}",0);
	Newline(out);
}

void Proto::PrintCrafterCpp(ostream& out) const {
	/* Copy to put the name uppercase */

	Printline(out,"#include \"" + protoName + ".h\"",0);
	Newline(out);
	Printline(out,"using namespace Crafter;",0);
	Printline(out,"using namespace std;",0);
	Newline(out);

	/* ReDefineActiveFields function */
	Printline(out,"void " + protoName + "::ReDefineActiveFields() {",0);

	Printline(out,"}",0);
	Newline(out);

	/* Craft function */
	Printline(out,"void " + protoName + "::Craft() {",0);

	Printline(out,"}",0);
	Newline(out);

	/* ReDefineActiveFields function */
	Printline(out,"string " + protoName + "::MatchFilter() const {",0);

	Printline(out,"}",0);
	Newline(out);

	Printline(out,"void " + protoName + "::ParseLayerData(ParseInfo* info) {",0);

	Printline(out,"}",0);
	Newline(out);

}

static inline bool fexists(const string& filename)
{
  ifstream ifile(filename.c_str());
  return ifile;
}

void Proto::PrintCpp() const {

	string out_const(protoName+"Constructor"+".cpp");

	std::ofstream file_const(out_const.c_str());

	if(PrintLicense(file_const,"../../LICENSE"))
		if(PrintLicense(file_const,"ProtoSource/LICENSE"))
			if(PrintLicense(file_const,"../LICENSE"))
				cerr << "[@] Unable to open the license file when writing header. " << endl;
	Newline(file_const);

	PrintConstructorCpp(file_const);

	if(fexists(protoName+"Craft.cpp"))
		return;

	string out_craft(protoName+"Craft"+".cpp");

	std::ofstream file_craft(out_craft.c_str());

	/* Print license */
	if(PrintLicense(file_craft,"../../LICENSE"))
		if(PrintLicense(file_craft,"ProtoSource/LICENSE"))
			if(PrintLicense(file_craft,"../LICENSE"))
				cerr << "[@] Unable to open the license file when writing header. " << endl;
	Newline(file_craft);

	PrintCrafterCpp(file_craft);

}

int Proto::PrintLicense(ostream& out, const string& name) const {
	/* Open the license file */
	ifstream file(name.c_str());

	/* String line */
	string line;

	if (file.is_open())
	{
		while (!file.eof())
		{
			getline(file,line);
			out << line << endl;
		}
	} else
		return 1;

	return 0;

}

void Proto::PrintDefinition(std::ostream& out) const {
	const_iterator it;

	for(it = begin() ; it != end() ; it++)
		out << "Fields.push_back(" + (*it)->ReturnDefinition() + ");" << endl;
}

Proto::~Proto() {
	iterator it_field;
	for(it_field = begin() ; it_field != end() ; ++it_field)
		delete (*it_field);
}

