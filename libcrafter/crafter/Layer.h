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
#include <ostream>
#include <stdexcept>
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

#include "Fields/Field.h"
#include "Payload.h"
#include "Utils/PrintMessage.h"
#include "InitCrafter.h"

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

		/* Pair of proto_id and top_layer (after binding) */
		struct BindPair {
			/* Proto ID of the next layer */
			short_word proto_next;
			/* Field container of the binded layer */
			FieldContainer Fields;
			BindPair() {/* */};
			BindPair(short_word proto_next, const FieldContainer& fc, size_t layer_size) :
				     proto_next(proto_next), Fields(fc) {/* */};
			~BindPair() {/*  */};
		};

		/* Table of binded layers */
		static std::map<short_word,std::vector<BindPair> > BindTable;

		/*
		 * Check if this layer is binded (if not returns zero,
		 * else the proto id of the binded layer)
		 */
		short_word CheckBinding() const;

    protected:

		friend void CraftLayer(Layer* layer);

		/* Layer constructor function definition */
		typedef Layer(*(*Constructor)());

		/* Number that identifies this layer protocol */
		short_word protoID;
		/* Name of the layer */
		std::string name;
		/* Raw data from the layer */
		byte* raw_data;
		/* Map of fields values and names */
		FieldContainer Fields;
		/* Payload of the Layer */
		Payload LayerPayload;
		/* Layer on the top of this one */
		Layer* BottomLayer;
		/* Layer on the Top of this one */
		Layer* TopLayer;

		/* ----------- Manipulating data functions ----------- */

		/* Set a Field value */
		template<class T>
		void SetFieldValue(size_t nfield, T HumanValue);
		/* Get value of a field */
		template<class T>
		T GetFieldValue(size_t nfield) const;

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

		/* Debug field */
		void PrintFieldsAdd() const {
			/* Free every Field allocated */
			std::vector<FieldInfo*>::const_iterator it_field;

			for (it_field = Fields.begin() ;  it_field != Fields.end() ; ++it_field) {
				std::cout << "field is at " << std::hex << (*it_field) << std::endl;;
			}
		};

		/*
		 * Function that checks if the field <FieldName> is active,
		 * and re-set the value according to the raw_data on the layer
		 */
		void RedefineField(size_t nfield);

		/* Get a pointer to a field of the layer */
		FieldInfo* GetFieldPtr(size_t nfield);

		/* Check if the field_name was set by the user */
		byte IsFieldSet(size_t nfield) const;

		/* Reset all field */
		void ResetFields();

		/* Reset all field */
		void ResetField(size_t nfield);

		/* Clone the layer given as an argument */
		void Clone(const Layer& layer);

		/* Put a Layer on the bottom of this one */
		void PushBottomLayer(Layer* bottom_layer) {
			BottomLayer = bottom_layer;
		};

		/* Put a Layer on the bottom of this one */
		void PushTopLayer(Layer* top_layer) {
			TopLayer = top_layer;
		};

		/* Get the remaining packet size in bytes */
		size_t GetRemainingSize() const;

		/*
		 * This function re-set the Active Fields on the layer. For
		 * default it does nothing. But, for example, the ICMP layer
		 * have some fields that depends on the type of message, so
		 * in function the active fields should be re-seted.
		 * This function is called after the construction of the layer
		 * from raw data.
		 */
		virtual void ReDefineActiveFields() {/* */};

		/*
		 * Function that defines the fields of this layer.
		 */
		virtual void DefineProtocol() = 0;

		/* This function returns a constructor of this class */
		virtual Constructor GetConstructor() const = 0;

		/*
		 * This function is the most important. With the information of
		 * the whole packet, it should complete some data in the layer.
		 * For example, the checksum, next protocol, size, etc.
		 */
		virtual void Craft() = 0;

		/* Add info to a filter for capture the matching packet */
		virtual std::string MatchFilter() const { return " "; };

		/* Print tha layer content and payload */
		virtual void PrintFields(std::ostream& str) const;
		virtual void PrintPayload(std::ostream& str) const;

	public:

		/* Friend classes */
		friend class Protocol;
		friend class Packet;

		/* Structure with information about the parsing of layers */
		struct ParseInfo {
			/* READ ONLY inside ParseData */
			/* Pointer to the original data, this should be set only once at the begging*/
			const byte* raw_data;
			/* Total length of the data */
			size_t total_size;

			/* UPDATE DATA inside ParseData */
			/* Current offset to read data on the raw pointer */
			size_t offset;
			/* Next layer to be pushed on the Packet stack */
			Layer* next_layer;
			/* Additional information that a layer may need to communicate to other layer */
			void* extra_info;
			/* Reach top of the packet */
			byte top;
			/* Constructor */
			ParseInfo() : raw_data(0), total_size(0), offset(0), next_layer(0), extra_info(0), top(0) {};
		};

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
		void HexDump(std::ostream& str = std::cout) const;

		/* Print the header in human readable form */
		void Print(std::ostream& str = std::cout) const;

		/* Print Raw data in string format */
		void RawString(std::ostream& str = std::cout) const;

		/* ------------ Class specific functions ------------- */

		/*
		 * This function construct the layer from raw data and
		 * returns the number of bytes read
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

		/* Set payload */
		void SetPayload (const Payload& payload);

		/* Add more stuff to the payload */
		void AddPayload (const Payload& payload);

		/* Copy the data into the pointer and returns the number of bytes copied */
		size_t GetPayload(byte* dst) const;

		/* Returns a constant reference to the payload */
		const Payload& GetPayload() const { return LayerPayload; };

		/* Returns the payload as a STL string */
		std::string GetStringPayload() const { return LayerPayload.GetString(); };

		/*
		 * Bind a layer to a protocol
		 * This mean that after bottom_layer should be a top_layer
		 * with protocol ID <proto_id>
		 */
		static void Bind(const Layer& bottom_layer, short_word proto_id);

		/* --------- Fields information functions ---------- */

		size_t GetFieldsSize() const { return Fields.size(); };
		FieldInfo* GetField(int i) const { return Fields[i]; };

        /* --------------- Move between layers ------------- */

        /* Get pointer to the layer on bottom */
        Layer *GetBottomLayer() const {
            return BottomLayer;
        };

        /* Get pointer to the layer on top */
        Layer *GetTopLayer() const {
            return TopLayer;
        };

		/* --------------------------------------------------- */

		virtual ~Layer();

	private:
		/*
		 * This function parse the data after the header is all set up.
		 * Basically, this function should update the ParseInfo structure
		 * to inform the decoder what should do on the next step.
		 * Checkout PacketDecoder.cpp!
		 *
		 * If there isn't a "next layer" to be created, this function
		 * should set the top flag to zero.
		 */
		virtual void ParseLayerData(ParseInfo* info);

		/* Function to call PutData and the ParseLayerData */
		void ParseData(ParseInfo* info);

	};

	class Protocol {
		/* Layer contructor function definition */
		typedef Crafter::Layer(*(*Constructor)());

		/* Static instance of this class. */
		static Protocol ProtoFactory;

		/* This prevent a creation of a Protocol class */
		Protocol () {InitCrafter();};
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

		virtual ~Protocol() {CleanCrafter();};
	};

	/* Verbose Mode */
	extern byte ShowWarnings;

}

template<class T>
void Crafter::Layer::SetFieldValue(size_t nfield, T HumanValue){
	/* Set the nfield value */
	Fields.SetField(nfield,HumanValue);

	/* And write the data into this layer */
	Fields[nfield]->Write(raw_data);
}

/* Get a pointer to a field */
template<class T>
T Crafter::Layer::GetFieldValue(size_t nfield) const {
	return Fields.GetField<T>(nfield);
}

#endif /* LAYER_H_ */
