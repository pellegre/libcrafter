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

#ifndef FIELDTYPE_H_
#define FIELDTYPE_H_

#include <iostream>
#include <map>
#include <stdint.h>
#include <ostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>

typedef uint32_t word;
typedef uint16_t short_word;
typedef uint8_t byte;

template<typename T>
T fromString(const std::string& str) {
	std::istringstream s(str);
	T t;
	s >> t;
	return t;
}

template<typename T>
std::string toString(const T& t) {
	std::ostringstream s;
	s << t;
	return s.str();
}

class FieldType {

protected:

	/* Name of the field */
	std::string name;
	/* Field type */
	std::string type;
	/* Type of the human value associated field */
	std::string value_type;

	/* Default value of this field */
	std::string default_value;

	typedef FieldType(*(*Constructor)(const std::string&));

	/* ---- Virtual functions ---- */

	/* Read from the stream */
	virtual void Read(std::ifstream& in) = 0;

public:

	FieldType(const std::string& name, const std::string& type, const std::string& value_type);

	/* ---- Virtual functions ---- */

	/* Read from the stream */
	virtual void ReadData(std::ifstream& in);
	/* Return a new statement with the correct arguments for the constructor */
	virtual std::string ReturnDefinition() const = 0;
	/* Return a constructor */
	virtual Constructor GetConstructor() const = 0;
	/* Get the size in bits of the field */
	virtual size_t Size() const = 0;

	/* Getters */
	std::string GetName() const { return name; };
	std::string GetType() const { return type; };
	std::string GetValueType() const { return value_type; };

	std::string GetDefaultSetter() const;

	/* Print the Get function */
	void PrintGet(std::ostream& out) const;

	/* Print the Set function */
	void PrintSet(std::ostream& out) const;

	virtual ~FieldType();
};

class BitsFieldType : public FieldType {
	std::string nword;
	std::string nbit;
	std::string size;
public:

	BitsFieldType(const std::string& name) : FieldType(name,"BitsField","word") { /* */ };
	void Read(std::ifstream& in) {
		in >> nword;
		in >> nbit;
		in >> size;
	}
	std::string ReturnDefinition() const {
		return "new " + type + "<" + size + "," + nbit + ">(\"" + name + "\"," + nword + ")";
	}
	static FieldType* Constructor(const std::string& name) { return new BitsFieldType(name); };
	size_t Size() const { return fromString<size_t>(size); };
	FieldType::Constructor GetConstructor() const { return BitsFieldType::Constructor; };
	~BitsFieldType() { /* */ };
};

/* ------- */

class BitFlagType : public FieldType {
	std::string nword;
	std::string nbit;
	std::string str_true;
	std::string str_flase;
public:

	BitFlagType(const std::string& name) : FieldType(name,"BitFlag","word") { /* */ };
	void Read(std::ifstream& in) {
		in >> nword;
		in >> nbit;
		in >> str_true;
		in >> str_flase;
	}
	std::string ReturnDefinition() const {
		return "new " + type + "<" + nbit + ">(\"" + name + "\"," + nword + "," + str_true + "," + str_flase + ")";
	}
	static FieldType* Constructor(const std::string& name) { return new BitFlagType(name); };
	size_t Size() const { return 1; };
	FieldType::Constructor GetConstructor() const { return BitFlagType::Constructor; };
	~BitFlagType() { /* */ };
};

/* ------- */
class XBitsFieldType : public FieldType {
	std::string nword;
	std::string nbit;
	std::string size;
	void Read(std::ifstream& in) {
		in >> nword;
		in >> nbit;
		in >> size;
	}
public:

	XBitsFieldType(const std::string& name) : FieldType(name,"XBitsField","word") { /* */ };
	std::string ReturnDefinition() const {
		return "new " + type + "<" + size + "," + nbit + ">(\"" + name + "\"," + nword + ")";
	}
	static FieldType* Constructor(const std::string& name) { return new XBitsFieldType(name); };
	size_t Size() const { return fromString<size_t>(size); };
	FieldType::Constructor GetConstructor() const { return XBitsFieldType::Constructor; };
	~XBitsFieldType() { /* */ };
};

/* ------- */

class BytesFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
	std::string size;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
		in >> size;
    }
public:

    BytesFieldType(const std::string& name) : FieldType(name,"BytesField","std::vector<byte> ") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "<" + size + ">(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new BytesFieldType(name); };
	size_t Size() const { return fromString<size_t>(size) * 8; };
    FieldType::Constructor GetConstructor() const { return BytesFieldType::Constructor; };
    ~BytesFieldType() { /* */ };
};

/* ------- */

class IPAddressType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

    IPAddressType(const std::string& name) : FieldType(name,"IPAddress","std::string") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new IPAddressType(name); };
    FieldType::Constructor GetConstructor() const { return IPAddressType::Constructor; };
	size_t Size() const { return 32; };
    ~IPAddressType() { /* */ };
};

/* ------- */

class IPv6AddressType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

    IPv6AddressType(const std::string& name) : FieldType(name,"IPv6Address","std::string") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new IPv6AddressType(name); };
    FieldType::Constructor GetConstructor() const { return IPv6AddressType::Constructor; };
	size_t Size() const { return 128; };
    ~IPv6AddressType() { /* */ };
};
/* ------- */

class MACAddressType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

    MACAddressType(const std::string& name) : FieldType(name,"MACAddress","std::string") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new MACAddressType(name); };
	size_t Size() const { return 48; };
    FieldType::Constructor GetConstructor() const { return MACAddressType::Constructor; };
    ~MACAddressType() { /* */ };
};

/* ------- */

class ByteFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

    ByteFieldType(const std::string& name) : FieldType(name,"ByteField","byte") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new ByteFieldType(name); };
	size_t Size() const { return 8; };
    FieldType::Constructor GetConstructor() const { return ByteFieldType::Constructor; };
    ~ByteFieldType() { /* */ };
};

/* ------- */

class TCPFlagsType : public FieldType {
	std::string nword;
	std::string nbit;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbit;
    }
public:

	TCPFlagsType(const std::string& name) : FieldType(name,"TCPFlags","word") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "<" + nbit +">(\"" + name + "\"," + nword + ")";
    }
    static FieldType* Constructor(const std::string& name) { return new TCPFlagsType(name); };
	size_t Size() const { return 9; };
    FieldType::Constructor GetConstructor() const { return TCPFlagsType::Constructor; };
    ~TCPFlagsType() { /* */ };
};

/* ------- */

class XByteFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

    XByteFieldType(const std::string& name) : FieldType(name,"XByteField","byte") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new XByteFieldType(name); };
	size_t Size() const { return 8; };
    FieldType::Constructor GetConstructor() const { return XByteFieldType::Constructor; };
    ~XByteFieldType() { /* */ };
};

/* ------- */

class ShortFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

    ShortFieldType(const std::string& name) : FieldType(name,"ShortField","short_word") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new ShortFieldType(name); };
	size_t Size() const { return 16; };
    FieldType::Constructor GetConstructor() const { return ShortFieldType::Constructor; };
    ~ShortFieldType() { /* */ };
};

/* ------- */

class ShortHostFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

    ShortHostFieldType(const std::string& name) : FieldType(name,"ShortHostField","short_word") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new ShortHostFieldType(name); };
	size_t Size() const { return 16; };
    FieldType::Constructor GetConstructor() const { return ShortHostFieldType::Constructor; };
    ~ShortHostFieldType() { /* */ };
};

/* ------- */

class XShortFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

	XShortFieldType(const std::string& name) : FieldType(name,"XShortField","short_word") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new XShortFieldType(name); };
	size_t Size() const { return 16; };
    FieldType::Constructor GetConstructor() const { return XShortFieldType::Constructor; };
    ~XShortFieldType() { /* */ };
};

/* ------- */

class WordFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

    WordFieldType(const std::string& name) : FieldType(name,"WordField","word") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new WordFieldType(name); };
	size_t Size() const { return 32; };
    FieldType::Constructor GetConstructor() const { return WordFieldType::Constructor; };
    ~WordFieldType() { /* */ };
};

/* ------- */

class WordHostFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

    WordHostFieldType(const std::string& name) : FieldType(name,"WordHostField","word") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new WordHostFieldType(name); };
	size_t Size() const { return 32; };
    FieldType::Constructor GetConstructor() const { return WordHostFieldType::Constructor; };
    ~WordHostFieldType() { /* */ };
};

/* ------- */

class XWordFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
    }
public:

	XWordFieldType(const std::string& name) : FieldType(name,"XWordField","word") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new XWordFieldType(name); };
	size_t Size() const { return 32; };
    FieldType::Constructor GetConstructor() const { return XWordFieldType::Constructor; };
    ~XWordFieldType() { /* */ };
};

/* ------- */

class StringFieldType : public FieldType {
	std::string nword;
	std::string nbyte;
	std::string size;
    void Read(std::ifstream& in) {
		in >> nword;
		in >> nbyte;
		in >> size;
    }
public:

    StringFieldType(const std::string& name) : FieldType(name,"StringField","std::string") { /* */ };
    std::string ReturnDefinition() const {
		return "new " + type + "<" + size + ">(\"" + name + "\"," + nword + "," + nbyte +")";
    }
    static FieldType* Constructor(const std::string& name) { return new StringFieldType(name); };
	size_t Size() const { return fromString<size_t>(size) * 8; };
    FieldType::Constructor GetConstructor() const { return StringFieldType::Constructor; };
    ~StringFieldType() { /* */ };
};

/* ------- */

class FieldFactory {

	/* Static instance of this class. */
	static FieldFactory Factory;

	/* This prevent a creation of a Factory class */
	FieldFactory () {
		BitsFieldType field0("TestBitsField");
		XBitsFieldType field1("TestXBitsField");
		BytesFieldType field2("TestBytesField");
		IPAddressType field3("TestIPAddress");
		MACAddressType field4("TestMACAddress");
		ByteFieldType field5("TestByteField");
		XByteFieldType field6("TestByteField");
		TCPFlagsType field7("TestByteField");
		ShortFieldType field8("TestShortField");
		XShortFieldType field9("TestShortField");
		WordFieldType field10("TestWordField");
		XWordFieldType field11("TestWordField");
		StringFieldType field12("TestStringField");
		BitFlagType field13("TestBitFlagField");
		IPv6AddressType field14("TestIPv6AddressField");
		WordHostFieldType field15("TestWordHostField");
		ShortHostFieldType field16("TestShortHostField");

		Factory.Register(&field0);
		Factory.Register(&field1);
		Factory.Register(&field2);
		Factory.Register(&field3);
		Factory.Register(&field4);
		Factory.Register(&field5);
		Factory.Register(&field6);
		Factory.Register(&field7);
		Factory.Register(&field8);
		Factory.Register(&field9);
		Factory.Register(&field10);
		Factory.Register(&field11);
		Factory.Register(&field12);
		Factory.Register(&field13);
		Factory.Register(&field14);
		Factory.Register(&field15);
		Factory.Register(&field16);
	};

	FieldFactory (const FieldFactory&);

	typedef FieldType(*(*Constructor)(const std::string&));

	/* Map of Register Fields */
	std::map<std::string,Constructor> FieldByName;

public:

	/* Register new field */
	void Register(FieldType* field) {
		/* Get this field Name */
		std::string fieldType = field->GetType();
		/* Do the registration process only once */
		if (FieldByName.find(fieldType) == FieldByName.end()) {
			/* Now save the Field into the table for future reference */
			FieldByName[fieldType] = field->GetConstructor();
		}
	};

	/* Return a field from the name */
	FieldType* GetFieldByName(const std::string& fieldType, const std::string& fieldName) {
		if (FieldByName.find(fieldType) != FieldByName.end())
			return FieldByName[fieldType](fieldName);
		else
			return 0;
	}

	/* Access to the factory for registration or construction */
	static FieldFactory* AccessFactory() {return &Factory;};

	virtual ~FieldFactory() { /* */ };

};

#endif /* FIELDTYPE_H_ */
