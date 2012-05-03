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

namespace Crafter {

/* Create a global and unique instance of the Protocol Factory */
Protocol Protocol::ProtoFactory ;

/* Verbose mode flag */
byte ShowWarnings;

}

void Crafter::Verbose(byte value) {
	Crafter::ShowWarnings = value;
}

short_word Crafter::CheckSum(short_word *buf, int nwords) {
	unsigned long sum;

	for(sum=0; nwords>0; nwords--)
			sum += *buf++;

	sum = (sum >> 16) + (sum &0xffff);

	sum += (sum >> 16);

	return (unsigned short)(~sum);
}

void Crafter::Layer::HexDump() const {

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

      // create a 64-character formatted output line:
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
         if(!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
         szBuf[lIndex2] = ucTmp;

         if (!(++lRelPos & 3))     // extra blank after 4 bytes
         {  lIndex++; szBuf[lIndex+2] = ' '; }
      }

      if (!(lRelPos & 3)) lIndex--;

      szBuf[lIndex  ]   = ' ';
      szBuf[lIndex+1]   = ' ';

      cout << szBuf << endl;

      buf.pData   += lOutLen;
      buf.lSize   -= lOutLen;
   }

   delete [] pAddressIn;
}

/* Print Payload */
void Crafter::Layer::RawString() const {
	/* Print raw data in hexadecimal format */
	for(size_t i = 0 ; i < size ; i++) {
		std::cout << "\\x";
		std::cout << std::hex << (unsigned int)((byte *)raw_data)[i];
	}

	LayerPayload.RawString();

	cout << endl;
}

void Crafter::Layer::Print() const {
	cout << "< ";
	cout << name << " (" << dec << GetSize() << " bytes) " << ":: ";
	/* Get iterator */
	set<string>::const_iterator it_active;

	for (it_active = ActiveFields.begin() ; it_active != ActiveFields.end() ; ++it_active) {
		cout << *it_active << "=";
		map<string,FieldInfo*>::const_iterator it_field = Fields.find((*it_active));
		(*it_field).second-> PrintField();
		cout << " ; ";
	}

	cout << "Payload = ";
	LayerPayload.Print();

	cout << ">" << endl;
}

/* Allocate a number of octets into the layer */
void Crafter::Layer::allocate_words(size_t nwords) {
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

/* Write a byte in the data */
void Crafter::Layer::write_byte(size_t nbyte, byte wbyte) {
	/* A simple write */
	((byte *)raw_data)[nbyte] = wbyte;
}

/* Set a bunch of bytes on the data */
void Crafter::Layer::write_bytes(size_t nbyte, size_t num, const byte* wbyte) {
	/* Write the bytes */
	for (unsigned int i = 0 ; i < num ; i++)
		( (byte *)raw_data + nbyte)[i] = wbyte[i];
}

/* Write the firts <nbits> bits in <value> to the raw_data from <ibit> */
void Crafter::Layer::write_bits(size_t ibit, size_t nbits, word value) {
	/* First, get on what word we should write */
	size_t nword = ibit/(sizeof(word)*8);
	/* Get in what bit of the word we have to write */
	unsigned char bit = ibit%(sizeof(word)*8);
	/* Get the byte where we have to write */
	size_t nbyte = nword * sizeof(word) + bit / 8;

	word net_value = 0;
	if (nbits == 8) {
		net_value = value;
		write_bytes(nbyte,1,(byte *)&net_value);
	}else if (nbits == 16) {
		net_value = htons((short_word)value);
		write_bytes(nbyte,2,(byte *)&net_value);
	}else if (nbits == 32) {
		net_value = htonl((word)value);
		write_bytes(nbyte,4,(byte *)&net_value);
	}

}

/* Define a new field for the layer */
void Crafter::Layer::define_field(const std::string& FieldName, FieldInfo* field) {
	/* Sanity check */
	assert(field->Get_endpos() > field->Get_bitpos());
	assert((field->Get_endpos() - field->Get_bitpos() + 1) <= 32);

	Fields[FieldName] = field;

	if (!overlap_flag)
		ActiveFields.insert(FieldName);
}

size_t Crafter::Layer::GetData(byte* data) const {
	/* Copy the data */
	if (raw_data) {
		for (size_t i = 0 ; i < GetHeaderSize() ; i++)
			data[i] = ((byte *)raw_data)[i];
	}

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
	/* Copy the data from the pointer and set the fields */
	map<string,FieldInfo*>::iterator it_field;

	for(it_field = Fields.begin() ; it_field != Fields.end() ; ++it_field) {
		/* Get position information of the field */
		size_t nword = (*it_field).second->Get_nword();
		size_t bitpos = (*it_field).second->Get_bitpos();
		size_t endpos = (*it_field).second->Get_endpos();

		/* Get the byte where we have to start writing */
		size_t nbyte = nword * sizeof(word) + bitpos / 8;
		/* Get the number of bits */
		size_t nbits = (endpos - bitpos + 1);

		word net_value = 0;
		if (nbits == 8) {
			net_value = ((byte *)data)[nbyte];
			(*it_field).second->SetField(net_value);
			write_bytes(nbyte,1,data+nbyte);
		}else if (nbits == 16) {
			net_value = ntohs( *((short_word *)(data + nbyte)) );
			(*it_field).second->SetField(net_value);
			write_bytes(nbyte,2,data+nbyte);
		}else if (nbits == 32) {
			net_value = ntohl( *((word *)(data + nbyte)) );
			(*it_field).second->SetField(net_value);
			write_bytes(nbyte,4,data+nbyte);
		}
	}

	return GetHeaderSize();
}

void Crafter::Layer::RedefineField(const std::string& FieldName) {

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

				/* Get the byte where we have to start writing */
				size_t nbyte = nword * sizeof(word) + bitpos / 8;
				/* Get the number of bits */
				size_t nbits = (endpos - bitpos + 1);

				/* Check intersection */
				if  ( ( ((*it).second->Get_bitpos() >= bitpos) && ((*it).second->Get_bitpos() <  endpos) ) ||
					  ( ((*it).second->Get_endpos() >  bitpos) && ((*it).second->Get_endpos() <= endpos) )  ) {
					/* Clear the overlapped field */
					OverlappedFields.insert(*it_active);
					FieldPtr->Clear();

					/* Read the value from the raw data and set the new field */
					word net_value = 0;
					if (nbits == 8) {
						net_value = ((byte *)raw_data)[nbyte];
						(*it).second->SetField(net_value);
					}else if (nbits == 16) {
						net_value = ntohs(((short_word *)raw_data)[nbyte/2]);
						(*it).second->SetField(net_value);
					}else if (nbits == 32) {
						net_value = ntohl(((word *)raw_data)[nbyte/4]);
						(*it).second->SetField(net_value);
					}
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
	LayerPayload.AddPayload(data);
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

Crafter::Layer::Layer() {
	/* Put size to zero */
	size = 0;
	raw_data = 0;
	/* Init bottom and top layer pointer */
	BottomLayer = 0;
	TopLayer = 0;
	overlap_flag = 0;
}

Crafter::Layer::Layer(const Layer& layer) {
	/* Put size to zero */
	size = 0;
	/* Init bottom and top layer pointer */
	BottomLayer = 0;
	TopLayer = 0;

	/* Copy Header information */
	name = layer.name;
	protoID = layer.protoID;
	overlap_flag = layer.overlap_flag;
	ActiveFields = layer.ActiveFields;

	/* Equal size */
	allocate_bytes(layer.size);

	/* Now create each field */
	map<string,FieldInfo*>::const_iterator it_field;

	/* Now copy the data from the other layer and set all fields */
	for (it_field = layer.Fields.begin() ; it_field != layer.Fields.end() ; ++it_field)
		Fields[(*it_field).first] = (*it_field).second->GetNewPointer();

	PutData((byte *)layer.raw_data);

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
	if (GetName() != right.GetName()) {
		std::cout << "[!] ERROR: Cannot convert " << right.GetName()<< " to " << GetName() << std::endl;
		exit(1);
	}

	Clone(right);
	return *this;
}

void Crafter::Layer::Clone(const Layer& layer) {
	/* Free every Field allocated */
	std::map<std::string,FieldInfo*>::iterator it_field_local;

	for (it_field_local = Fields.begin() ;  it_field_local != Fields.end() ; ++it_field_local) {
		delete (*it_field_local).second;
	}

	/* Delete memory allocated */
	if (size)
		delete [] raw_data;

	/* Put size to zero */
	size = 0;
	/* Init bottom and top layer pointer */
	BottomLayer = 0;
	TopLayer = 0;

	/* Copy Header information */
	name = layer.name;
	protoID = layer.protoID;
	overlap_flag = layer.overlap_flag;
	ActiveFields = layer.ActiveFields;

	/* Equal size */
	if(layer.size) allocate_bytes(layer.size);

	/* Now create each field */
	map<string,FieldInfo*>::const_iterator it_field;

	/* Now copy the data from the other layer and set all fields */
	for (it_field = layer.Fields.begin() ; it_field != layer.Fields.end() ; ++it_field)
		Fields[(*it_field).first] = (*it_field).second->GetNewPointer();

	PutData((byte *)layer.raw_data);

	/* Copy the payload, if any */
	size_t npayload = layer.LayerPayload.GetSize();

	byte* payload = new byte[npayload];

	layer.LayerPayload.GetPayload(payload);

	/* Finally, set the payload */
	SetPayload(payload,npayload);

	/* And delete the allocated buffer */
	delete [] payload;
}

FieldInfo* Crafter::Layer::GetFieldPtr(const std::string& field_name) {
	/* Return the value that is on teh table */
	std::map<std::string,FieldInfo*>::const_iterator it;

	it = Fields.find(field_name);

	if (it == Fields.end()) {
		std::cerr << "[!] ERROR: No field " << "<" << field_name << ">" << " defined in layer " << name << ". Aborting!" << std::endl;
		exit(1);
	}

	return ((*it).second);
}

byte Crafter::Layer::IsFieldSet(const std::string& FieldName) const {
	/* Return the value that is on the table */
	std::map<std::string,FieldInfo*>::const_iterator it;

	it = Fields.find(FieldName);

	if (it == Fields.end()) {
		std::cerr << "[!] ERROR: No field " << "<" << FieldName << ">" << " defined in layer " << name << ". Aborting!" << std::endl;
		exit(1);
	}

	return ((*it).second)->IsFieldSet();
}

byte Crafter::Layer::IsFieldSet(const FieldInfo* field_ptr) const {
	return field_ptr->IsFieldSet();
}

void Crafter::Layer::ResetFields() {
	/* Return the value that is on teh table */
	std::map<std::string,FieldInfo*>::iterator it_field;

	for (it_field = Fields.begin() ;  it_field != Fields.end() ; ++it_field)
		(*it_field).second->ResetField();

}

void Crafter::Layer::ResetField(const std::string& field_name) {
	/* Return the value that is on teh table */
	std::map<std::string,FieldInfo*>::const_iterator it;

	it = Fields.find(field_name);

	if (it == Fields.end()) {
		std::cerr << "[!] ERROR: No field " << "<" << field_name << ">" << " defined in layer " << name << ". Aborting!" << std::endl;
		exit(1);
	}

	((*it).second)->ResetField();
}

void Crafter::Layer::ResetField(FieldInfo* field_ptr) {
	field_ptr->ResetField();
}

byte Crafter::RNG8() {return rand()%256; }
short_word Crafter::RNG16() {return rand()%65536; }
word Crafter::RNG32() {return 2 * rand(); }

Crafter::Layer::~Layer() {
	/* Free every Field allocated */
	std::map<std::string,FieldInfo*>::iterator it_field;

	for (it_field = Fields.begin() ;  it_field != Fields.end() ; ++it_field) {
		delete (*it_field).second;
	}

	/* Delete memory allocated */
	if (size)
		delete [] raw_data;
}
