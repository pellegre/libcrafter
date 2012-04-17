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


#ifndef LAYER_H_
#define LAYER_H_

#include <iostream>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <arpa/inet.h>
#include <cctype>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <netinet/in.h>
#include <libnet.h>

#include "Field.h"
#include "Payload.h"
#include "PrintMessage.h"

typedef uint32_t word;
typedef uint16_t short_word;
typedef uint8_t byte;

namespace Crafter {

	short_word CheckSum(short_word *buf, int nwords);

	/* RNGs */
	byte RNG8();
	short_word RNG16();
	word RNG32();

	/* Verbose mode of the library */
	void Verbose(byte value);

	class Layer {
		/* Size in bytes of the header, not including the payload */
		size_t size;
		/* Size in bytes of the header including the payload */
		size_t bytes_size;
	protected:

		/* Layer constructor function definition */
		typedef Layer(*(*Constructor)());
		/* Map of Field and the corresponding information */
		typedef std::map<std::string,FieldInfo*> MapFieldInfo;

		/* Number that identifies this layer protocol */
		short_word protoID;
		/* Name of the layer */
		std::string name;
		/* Raw data from the layer */
		byte* raw_data;
		/* List of active fields on the Layer */
		std::set<std::string> ActiveFields;
		/* Map of fields values and names */
		MapFieldInfo Fields;
		/* Payload of the Layer */
		Payload LayerPayload;
		/* Layer on the top of this one */
		Layer* BottomLayer;
		/* Layer on the Top of this one */
		Layer* TopLayer;

		/* ----------- Manipulating data functions ----------- */

		/* Write a byte in the data */
		void write_byte(size_t nbyte, byte wbyte);
		/* Set a bunch of bytes on the data */
		void write_bytes(size_t nbyte, size_t num, const byte* wbyte);
		/* Write the firts <nbits> bits in <value> to the raw_data from <ibit>*/
		void write_bits(size_t ibit, size_t nbits, word value);

		/* Set a Field value */
		template <class T>
		void SetFieldValue(const std::string& FieldName, T HumanValue);
		/* Get value of a field */
		template<class T>
		T GetFieldValue(const std::string& FieldName) const;
		/* Get a pointer of this Layer */
		template<class T>
		T* GetLayerPtr(const std::string& FieldName) const;

		/* Set name of the layer */
		void SetName(const std::string& _name) { name = _name; };
		/* Set proto ID of the layer */
		void SetprotoID(const short_word _protoID) { protoID = _protoID; };

		/* ---------------- Memory Management ---------------- */

		/* Allocate a number of words into the layer */
		void allocate_words(size_t nwords);

		/* Allocate a number of bytes into the layer */
		void allocate_bytes(size_t nbytes);

		/* ---------- Field manipulation functions ----------- */

		/* Define a new field for the layer */
		void define_field(const std::string& FieldName, FieldInfo* field);

		/* --------------------------------------------------- */

		/* Debug field */
		void PrintFieldsAdd() const {
			/* Free every Field allocated */
			std::map<std::string,FieldInfo*>::const_iterator it_field;

			for (it_field = Fields.begin() ;  it_field != Fields.end() ; ++it_field) {
				std::cout << (*it_field).first << " is at " << std::hex << (*it_field).second << std::endl;;
			}
		};

		/*
		 * Function that checks if the field <FieldName> is active,
		 * and re-set the value according to the raw_data on the layer
		 */
		void RedefineField(const std::string& FieldName);

		/* Check if the field_name was set by the user */
		byte IsFieldSet(const std::string& FieldName) const;

		/* Reset all field */
		void ResetFields();

		/* Reset all field */
		void ResetField(const std::string& field_name);

		/* Clone the layer given as an argument */
		void Clone(const Layer& layer);

		/* Put a Layer on the bottom of this one */
		void PushBottomLayer(Layer* bottom_layer) {
			BottomLayer = bottom_layer;
		};

		/* Get pointer to the layer on top */
		Layer *GetBottomLayer() const {
			return BottomLayer;
		};

		/* Put a Layer on the bottom of this one */
		void PushTopLayer(Layer* top_layer) {
			TopLayer = top_layer;
		};

		/* Get pointer to the layer on top */
		Layer *GetTopLayer() const {
			return TopLayer;
		};

		/* Get the remaining packet size in bytes */
		size_t GetRemainingSize() const;

		/*
		 * This function re-set the Active Fields on the layer. For
		 * default it does nothing. But, for example, the ICMP layer
		 * have some fields that depends on the type of message, so
		 * in function of that the active fields should be re-seted.
		 * This function is called after the construction of the layer
		 * from raw data.
		 */
		virtual void ReDefineActiveFields() {/* */};

		/*
		 * Function that defines the protocol of this layer. Name,
		 * fields, ID, etc.
		 */
		virtual void DefineProtocol() = 0;

		/* This function returns a contructor of this class */
		virtual Constructor GetConstructor() const = 0;

		/*
		 * This function is the most important. With the information of
		 * the whole packet, it should complete some data in the layer.
		 * For example, the checksum, next protocol, size, etc. Finally,
		 * the final craft layer should be write out on <buffer>.
		 */
		virtual void Craft() = 0;

		/* Add info to a filter for capture the matching packet */
		virtual std::string MatchFilter() const { return " "; };

		/* Put data into a libnet context calling the libnet_build* function */
		virtual void LibnetBuild(libnet_t *l) { };

	public:

		/* Friend classes */
		friend class Protocol;
		friend class Packet;

		/* Default constructor */
		Layer();

		/* Copy Constructor */
		Layer(const Layer&);

		/* Assignment */
		virtual Layer& operator=(const Layer& right);

		/* ----------------------- Data --------------------- */

		/* Get the name of the layer */
		std::string GetName() const { return name; };

		/* Get ID on the Protocol */
		short_word GetID() const { return protoID; };

		/* Get size in BYTES of the header (including payload) */
		size_t GetSize() const {
			return bytes_size;
		};

		/* Get header size in bytes */
		size_t GetHeaderSize() const {
			return size;
		}

		/* Get the size of the payload */
		size_t GetPayloadSize() const {
			return LayerPayload.GetSize();
		};

		/* -------------------- Print Data ------------------- */

		/* Make an hexdump of the Layer */
		void HexDump() const;

		/* Print the header in human readable form */
		virtual void Print() const;

		/* Print Raw data in string format */
		void RawString() const;

		/* ------------ Class specific functions ------------- */

		/*
		 * This function construct the layer from raw data and
		 * returns the pointer at the end of the buffer
		 */
		size_t PutData(const byte* data);

		/* Get data from this layer to the top */
		size_t GetData(byte* buffer) const;

		/* Just get the data of this layer */
		size_t GetRawData(byte* buffer) const;

		/* --------- Payload manipulation functions ---------- */

		/* Set payload */
		void SetPayload (const byte *data, int ndata);

		/* Add more stuff to the payload */
		void AddPayload (const byte* data, int ndata);

		/* Set payload */
		void SetPayload (const char *data);

		/* Add more stuff to the payload */
		void AddPayload (const char* data);

		/* Copy the data into the pointer and returns the number of bytes copied */
		size_t GetPayload(byte* dst) const;

		/* Returns a constant reference to the payload */
		const Payload& GetPayload() const { return LayerPayload; };

		/* Returns the payload as a STL string */
		std::string GetStringPayload() const { return std::string((char*)(LayerPayload.storage),LayerPayload.size); };
		/* --------------------------------------------------- */

		virtual ~Layer();
	};

	class Protocol {
		/* Layer contructor function definition */
		typedef Crafter::Layer(*(*Constructor)());

		/* Static instance of this class. */
		static Protocol ProtoFactory;

		/* This prevent a creation of a Protocol class */
		Protocol () {};
		Protocol (const Protocol&);

		/* Map of Register Protocols */
		std::map<std::string,Constructor> RegProtoByName;
		std::map<short_word,Constructor> RegProtoByID;

		/* Get a register of ProtoIDs in function of Proto Names */
		std::map<short_word, std::string> ProtoIDToName;

		/* Get a register of Proto Names in function of Proto IDs */
		std::map<std::string, short_word> NameToProtoID;

		/* Layer objects can modified private values of Protocol Egg */
		friend class Layer;

	public:

		/* Register new Protocol */
		void Register(Crafter::Layer* ProtoLayer) {
			/* Get this Layer Name */
			std::string ProtoName = ProtoLayer -> GetName();
			/* Do the registration process only once */
			if (RegProtoByName.find(ProtoName) == RegProtoByName.end()) {

				/* Now save the Protocol into the table for future reference */
				RegProtoByName[ProtoLayer->GetName()] = ProtoLayer->GetConstructor();
				RegProtoByID[ProtoLayer->GetID()] = ProtoLayer->GetConstructor();

				NameToProtoID[ProtoLayer->GetName()] = ProtoLayer->GetID();
				ProtoIDToName[ProtoLayer->GetID()] = ProtoLayer->GetName();
			}
		};

		/* Return a layer from the protocol name */
		Crafter::Layer* GetLayerByName(const std::string& ProtoName) {
			if (RegProtoByName.find(ProtoName) != RegProtoByName.end())
				return RegProtoByName[ProtoName]();
			else
				return 0;
		}

		/* Return a layer from the protocol ID */
		Crafter::Layer* GetLayerByID(const short_word ProtoID) {
			if (RegProtoByID.find(ProtoID) != RegProtoByID.end())
				return RegProtoByID[ProtoID]();
			else
				return 0;
		}

		/* Get a Protocol Name */
		std::string GetProtoName(short_word protoID) {
			if (ProtoIDToName.find(protoID) != ProtoIDToName.end())
				return ProtoIDToName[protoID];
			else
				return "Unknown";
		}

		short_word GetProtoID(std::string protoName) {
			if (NameToProtoID.find(protoName) != NameToProtoID.end())
				return NameToProtoID[protoName];
			else
				return 0;
		}

		/* Access to the factory for registration or construction */
		static Protocol* AccessFactory() {return &ProtoFactory;};

		virtual ~Protocol() {};
	};

	/* Verbose Mode */
	extern byte ShowWarnings;

}

template<class T>
void Crafter::Layer::SetFieldValue(const std::string& FieldName, T HumanValue){

	/* Set the field value on the table */
	std::map<std::string,FieldInfo*>::iterator it;

	it = Fields.find(FieldName);

	if (it == Fields.end()) {
		std::cerr << "[!] ERROR: No field " << "<" << FieldName << ">" << " defined in layer " << name << ". Aborting!" << std::endl;
		exit(1);
	}

	std::set<std::string> OverlappedFields;

	/* First, check if the field is active */
	if(ActiveFields.find(FieldName) == ActiveFields.end()) {
		/* If the field is not active, it can be ovelarping some other field */
		std::set<std::string>::iterator it_active;

		for (it_active = ActiveFields.begin() ; it_active != ActiveFields.end() ; ++it_active) {
			FieldInfo* FieldPtr = Fields[(*it_active)];
			/* Get information of the active fields */
			size_t nword = FieldPtr->Get_nword();

			/* Check if the fields are in the same word */
			if ((*it).second->Get_nword() == nword) {
				size_t bitpos = FieldPtr->Get_bitpos();
				size_t endpos = FieldPtr->Get_endpos();

				/* Check intersection */
				if  ( ( ((*it).second->Get_bitpos() >= bitpos) && ((*it).second->Get_bitpos() <  endpos) ) ||
					  ( ((*it).second->Get_endpos() >  bitpos) && ((*it).second->Get_endpos() <= endpos) )  ) {
					OverlappedFields.insert(*it_active);
					FieldPtr->Clear();
				}

			}
		}
		/* And push it into the active fields set */
		ActiveFields.insert(FieldName);
	}

	/* Remove overlapped fields, if any */
	std::set<std::string>::iterator it_over;

	for (it_over = OverlappedFields.begin() ; it_over != OverlappedFields.end() ; ++it_over)
		ActiveFields.erase(*it_over);

	dynamic_cast<GeneralField<T>* >((*it).second)->HumanToNetwork(HumanValue);

	word value = (*it).second->GetNetworkValue();

	if ( !(*it).second->IsFieldSet() )
		(*it).second->FieldSetted();

	/* Get position information of the field */
	size_t nword = (*it).second->Get_nword();
	size_t bitpos = (*it).second->Get_bitpos();
	size_t endpos = (*it).second->Get_endpos();

	/* Get length of the field */
	size_t length = endpos - bitpos + 1;

	/* Now, write the value into the raw data */
	write_bits(sizeof(word)*8*nword + bitpos, length, value);

}

/* Get a pointer to a field */
template<class T>
T Crafter::Layer::GetFieldValue(const std::string& FieldName) const {
	/* Return the value that is on teh table */
	std::map<std::string,FieldInfo*>::const_iterator it;

	it = Fields.find(FieldName);

	if (it == Fields.end()) {
		std::cerr << "[!] ERROR: No field " << "<" << FieldName << ">" << " defined in layer " << name << ". Aborting!" << std::endl;
		exit(1);
	}

	return dynamic_cast<GeneralField<T>* >((*it).second)->GetHumanRead();
}

template<class T>
T* Crafter::Layer::GetLayerPtr(const std::string& FieldName) const {
	/* Return the value that is on the table */
	std::map<std::string,FieldInfo*>::const_iterator it;

	it = Fields.find(FieldName);

	if (it == Fields.end()) {
		std::cerr << "[!] ERROR: No field " << "<" << FieldName << ">" << " defined in layer " << name << ". Aborting!" << std::endl;
		exit(1);
	}

	return dynamic_cast<T* >((*it).second);
}

#endif /* LAYER_H_ */
