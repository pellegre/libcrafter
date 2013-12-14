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

#include "Layer.h"

using namespace std;
using namespace Crafter;

/* Table of binded layers */
map<short_word,vector<Layer::BindPair> > Layer::BindTable;

namespace Crafter {

	/* Create a global and unique instance of the Protocol Factory */
	Protocol Protocol::ProtoFactory ;

	/* Verbose mode flag */
	byte ShowWarnings;

}


void Crafter::Verbose(byte value) {
	Crafter::ShowWarnings = value;
}

void Crafter::Layer::Bind(const Layer& bottom_layer, short_word proto_id) {
	short_word bottom_proto = bottom_layer.GetID();
	short_word top_proto = proto_id;

	BindTable[bottom_proto].push_back(BindPair(top_proto,bottom_layer.Fields,bottom_layer.GetSize()));
}

short_word Crafter::Layer::CheckBinding() const {
	map<short_word,vector<Layer::BindPair> >::const_iterator it = BindTable.find(GetID());
	short_word next_proto = 0;

	if(it != BindTable.end()) {

		/* Allocate space for layers */
		byte* this_layer = new byte[GetSize()];
		byte* comp_layer = new byte[GetSize()];

		/* Iterate through each BindPair */
		vector<Layer::BindPair>::const_iterator it_bind;

		for(it_bind = (*it).second.begin() ; it_bind != (*it).second.end() ; it_bind++) {
			memset(this_layer,0,GetSize());
			memset(comp_layer,0,GetSize());

			/* Get the binded pair */
			BindPair bp = (*it_bind);
			/* Number of fields */
			size_t field_count = Fields.size();

			/* Sanity check */
			if(field_count != bp.Fields.size())
				return 0;

			/* OK, lets compare both layers */
			for(size_t field = 0 ; field < field_count ; field++) {
				FieldInfo* field_ptr = bp.Fields[field];
				/* Write fields */
				if(field_ptr->IsFieldSet()) {
					Fields[field]->Write(this_layer);
					field_ptr->Write(comp_layer);
				}
			}

			/* Compare both layers */
			if(!memcmp(this_layer,comp_layer,GetSize())) {
				next_proto = bp.proto_next;
				break;
			}
		}

		delete [] this_layer;
		delete [] comp_layer;
	}

	return next_proto;
}

short_word Crafter::CheckSum(short_word *buf, int nwords) {
	unsigned long sum;

	for(sum=0; nwords>0; nwords--)
			sum += *buf++;

	sum = (sum >> 16) + (sum &0xffff);

	sum += (sum >> 16);

	return (unsigned short)(~sum);
}

void Crafter::Layer::HexDump(ostream& str) const {

	size_t  lSize = bytes_size;

	byte *pAddressIn = new byte[lSize];

	for (size_t i = 0 ; i < size ; i++)
		pAddressIn[i] = ((byte *)raw_data)[i];

	LayerPayload.GetPayload(pAddressIn + size);

	char szBuf[100];
	long lIndent = 1;
	long lOutLen, lIndex, lIndex2, lOutLen2;
	long lRelPos;
	struct { char *pData; unsigned long lSize; } buf;
	unsigned char *pTmp,ucTmp;
	unsigned char *pAddress = (unsigned char *)pAddressIn;

   buf.pData   = (char *)pAddress;
   buf.lSize   = lSize;

   while (buf.lSize > 0)
   {
      pTmp     = (unsigned char *)buf.pData;
      lOutLen  = (int)buf.lSize;
      if (lOutLen > 16)
          lOutLen = 16;

      /* Create a 64-character formatted output line */
      sprintf(szBuf, "                              "
                     "                      "
                     "    %08lX", (long unsigned int) (pTmp-pAddress));
      lOutLen2 = lOutLen;

      for(lIndex = 1+lIndent, lIndex2 = 53-15+lIndent, lRelPos = 0;
          lOutLen2;
          lOutLen2--, lIndex += 2, lIndex2++
         )
      {
         ucTmp = *pTmp++;

         sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
         if(!isprint(ucTmp))  ucTmp = '.'; /* NonPrintable char */
         szBuf[lIndex2] = ucTmp;

         if (!(++lRelPos & 3))             /* Extra blank after 4 bytes */
         {  lIndex++; szBuf[lIndex+2] = ' '; }
      }

      if (!(lRelPos & 3)) lIndex--;

      szBuf[lIndex  ]   = ' ';
      szBuf[lIndex+1]   = ' ';

      str << szBuf << endl;

      buf.pData   += lOutLen;
      buf.lSize   -= lOutLen;
   }

   delete [] pAddressIn;
}

/* Print Payload */
void Crafter::Layer::RawString(ostream& str) const {
	/* Print raw data in hexadecimal format */
	for(size_t i = 0 ; i < size ; i++) {
		str << "\\x";
		str << std::hex << (unsigned int)((byte *)raw_data)[i];
	}

	LayerPayload.RawString(str);

	str << endl;
}

void Crafter::Layer::PrintFields(std::ostream& str) const {
	/* Print the fields */
	Fields.Print(str);
}

void Crafter::Layer::PrintPayload(std::ostream& str) const {
	str << "Payload = ";
	LayerPayload.Print(str);
}

void Crafter::Layer::Print(std::ostream& str) const {
	str << "< ";
	str << name << " (" << dec << GetSize() << " bytes) " << ":: ";

	/* Print each one of the fields */
	PrintFields(str);

	if(GetPayloadSize())
		/* Also print the payload */
		PrintPayload(str);

	str << ">" << endl;
}

/* Allocate a number of octets into the layer */
void Crafter::Layer::allocate_words(size_t nwords) {
	/* Delete memory allocated */
	if (size)
		delete [] raw_data;

	/* Set the size */
	size = nwords * sizeof(word);
	/* Size in bytes of the header */
	bytes_size = nwords * sizeof(word);

	/* Allocate the raw data buffer */
	raw_data = new byte[size];

	/* And set the buffer to zero */
	for (unsigned int i = 0 ; i < size ; i++)
		raw_data[i] = 0x00;

}

/* Allocate a number of bytes into the layer */
void Crafter::Layer::allocate_bytes(size_t nbytes) {
	/* Delete memory allocated */
	if (size)
		delete [] raw_data;

	/* Set the size */
	size = nbytes;
	/* Size in bytes of the header */
	bytes_size = nbytes;

	/* Allocate the raw data buffer */
	raw_data = new byte[nbytes];

	/* And set the buffer to zero */
	for (unsigned int i = 0 ; i < size ; i++)
		raw_data[i] = 0x00;

}

size_t Crafter::Layer::GetData(byte* data) const {
	/* Copy the data */
	if (raw_data)
		memcpy(data,raw_data,GetHeaderSize());

	/* Put Payload, if any */
	size_t npayload = LayerPayload.GetPayload(data + GetHeaderSize());

	/* Copy the data */
	if(!TopLayer)
		return GetHeaderSize() + npayload;
	else
		return GetHeaderSize() + npayload + TopLayer->GetData(data + GetHeaderSize() + npayload);

}

size_t Crafter::Layer::GetRawData(byte* data) const {
	/* Copy the data */
	if (raw_data) {
		for (size_t i = 0 ; i < GetHeaderSize() ; i++)
			data[i] = ((byte *)raw_data)[i];
	}

	/* Put Payload, if any */
	size_t npayload = LayerPayload.GetPayload(data + GetHeaderSize());

	return GetHeaderSize() + npayload;
}

size_t Crafter::Layer::PutData(const byte* data) {
	/* Set the fields from the data provided */
	Fields.ApplyAll(&FieldInfo::Read,data);

	/* Redefine the fields in function of packet values */
	ReDefineActiveFields();

	/* And write the data into the raw pointer */
	memcpy(raw_data,data,GetHeaderSize());

	return GetHeaderSize();
}

void Crafter::Layer::ParseData(ParseInfo* info) {
	/* Construct this header from the data */
	PutData(info->raw_data + info->offset);
	info->offset += GetSize();

	/* Once we have all the fields set, parse the information on this header */
	ParseLayerData(info);
	/*
	 * After this, the info structure is updated with information on what the
	 * decoder should do in the next step
	 */
}

void Crafter::Layer::ParseLayerData(ParseInfo* info) {
	/* No more layers, default */
	info->top = 1;
}

void Crafter::Layer::RedefineField(size_t nfield) {
	/* Set field as active */
	Fields.SetActive(nfield);
}

size_t Crafter::Layer::GetRemainingSize() const {
	if (!TopLayer)
		return GetSize();
	else
		return GetSize() + TopLayer->GetRemainingSize();
}

/* Payload manipulation functions */

/* Set payload */
void Crafter::Layer::SetPayload (const byte *data, int ndata) {
	LayerPayload.SetPayload(data,ndata);
	bytes_size = size + LayerPayload.GetSize();
}

/* Add more stuff to the payload */
void Crafter::Layer::AddPayload (const byte* data, int ndata) {
	LayerPayload.AddPayload(data,ndata);
	bytes_size = size + LayerPayload.GetSize();
}

/* Set payload */
void Crafter::Layer::SetPayload (const char *data) {
	LayerPayload.SetPayload(data);
	bytes_size = size  + LayerPayload.GetSize();
}

/* Add more stuff to the payload */
void Crafter::Layer::AddPayload (const char* data) {
	LayerPayload.AddPayload(data);
	bytes_size = size + LayerPayload.GetSize();
}

/* Set payload */
void Crafter::Layer::SetPayload (const Payload& data)  {
	LayerPayload.SetPayload(data);
	bytes_size = size + LayerPayload.GetSize();
}

/* Add more stuff to the payload */
void Crafter::Layer::AddPayload (const Payload& data) {
	LayerPayload.AddPayload(data);
	bytes_size = size + LayerPayload.GetSize();
}

/* Copy the data into the pointer and returns the number of bytes copied */
size_t Crafter::Layer::GetPayload(byte* dst) const {
	return LayerPayload.GetPayload(dst);
}

Crafter::Layer::Layer() : size(0), bytes_size(0), raw_data(0), BottomLayer(0), TopLayer(0) { }

Crafter::Layer::Layer(const Layer& layer) {
	/* Put size to zero */
	size = 0;
	/* Init bottom and top layer pointer */
	BottomLayer = 0;
	TopLayer = 0;

	/* Copy Header information */
	name = layer.name;
	protoID = layer.protoID;

	/* Equal size */
	allocate_bytes(layer.size);

	/* Copy the fields from the other layer */
	Fields = layer.Fields;

	PutData((const byte *)layer.raw_data);

	/* Copy the payload, if any */
	size_t npayload = layer.LayerPayload.GetSize();

	byte* payload = new byte[npayload];

	layer.LayerPayload.GetPayload(payload);

	/* Finally, set the payload */
	SetPayload(payload,npayload);

	/* And delete the allocated buffer */
	delete [] payload;
}

Layer& Crafter::Layer::operator=(const Layer& right) {

	/* Sanity check */
	if (GetName() != right.GetName())
		throw runtime_error("Cannot convert " + right.GetName() + " to " + GetName());

	Clone(right);
	return *this;
}

void Crafter::Layer::Clone(const Layer& layer) {
	/* Delete memory allocated */
	if (size)
		delete [] raw_data;

	/* Put size to zero */
	size = 0;
	/* Initialize bottom and top layer pointer */
	BottomLayer = 0;
	TopLayer = 0;

	/* Copy Header information */
	name = layer.name;
	protoID = layer.protoID;

	/* Equal size */
	if(layer.size) allocate_bytes(layer.size);

	/* Copy the fields from the other layer */
	Fields = layer.Fields;

	PutData((const byte *)layer.raw_data);

	/* Copy the payload, if any */
	size_t npayload = layer.LayerPayload.GetSize();

	byte* payload = new byte[npayload];

	layer.LayerPayload.GetPayload(payload);

	/* Finally, set the payload */
	SetPayload(payload,npayload);

	/* And delete the allocated buffer */
	delete [] payload;
}

FieldInfo* Crafter::Layer::GetFieldPtr(size_t nfield) {
	return Fields[nfield];
}

byte Crafter::Layer::IsFieldSet(size_t nfield) const {
	return Fields[nfield]->IsFieldSet();
}

void Crafter::Layer::ResetFields() {
	Fields.Apply(&FieldInfo::ResetField);
}

void Crafter::Layer::ResetField(size_t nfield) {
	Fields[nfield]->ResetField();
}

byte Crafter::RNG8() {return rand()%256; }
short_word Crafter::RNG16() {return rand()%65536; }
word Crafter::RNG32() {return 2 * rand(); }

Crafter::Layer::~Layer() {
	/* Delete memory allocated */
	if (size)
		delete [] raw_data;
}
