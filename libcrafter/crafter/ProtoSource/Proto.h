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

#ifndef PROTO_H_
#define PROTO_H_

#include <iostream>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

#include "FieldType.h"

class Proto : public std::vector<FieldType*> {

	/* Protocol data */
	std::string protoName;

	/* Protocol ID */
	std::string protoID;

	/* Protocol Size */
	size_t protoSize;

	Proto(const Proto& p) { /* */ };

	/* Print license header */
	int PrintLicense(std::ostream& out, const std::string& name) const;

	/* Print the source file */
	void PrintConstructorCpp(std::ostream& out) const;
	void PrintCrafterCpp(std::ostream& out) const;

public:
	Proto(const std::string& name, const std::string& id);

	/* Print the header */
	void PrintHdr() const;

	/* Print the source file */
	void PrintCpp() const;

	/* Print parsed fields definition */
	void PrintDefinition(std::ostream& out) const;

	void SetProtoName(const std::string& name) { protoName = name; };
	void SetProtoID(short_word id) { protoID = id; };
	void SetProtoSize(size_t size) { protoSize = size; };

	std::string GetProtoName() const { return protoName; };
	std::string GetProtoID() const { return protoID; };
	size_t GetProtoSize() const { return protoSize; };

	virtual ~Proto();
};

struct convert {
   void operator()(char& c) { c = toupper((unsigned char)c); }
};

std::string toUpper(std::string uperName);

#endif /* PROTO_H_ */
