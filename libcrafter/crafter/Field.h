/*
Copyright (C) 2012 Pellegrino E.

This file is part of libcrafter

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/


#ifndef FIELD_H_
#define FIELD_H_

#include <iostream>
#include "IPResolver.h"

typedef uint32_t word;
typedef uint8_t byte;

namespace Crafter {

	class FieldInfo {
	protected:
		size_t nword;   /* In which word is the field */
		size_t bitpos;  /* Start bit position of the field inside the word */
		size_t endpos;  /* Length of the field in bytes */
		word value;     /* Field value (first <length> bits in word) */
		byte field_set; /* Flag if field was set by the user */
	public:
		/* Construct Field */
		FieldInfo(size_t _nword = 0, size_t _bitpos = 0, size_t _endpos = 0, word _value = 0) :
			nword(_nword), bitpos(_bitpos), endpos(_endpos), value(_value) { field_set = 0; };

		/* Set value */
		void SetNetworkValue(word _value) { value = _value; };

		/* Get Value */
		word GetNetworkValue() const { return value; };

		/* Set Human Value of the Field */
		virtual void SetField(word _value) = 0;

		/* Get a new pointer of a field with a copy of the specific data */
		virtual FieldInfo* NewPointer() const = 0;

		/* Get a new pointer of a copy of this field information */
		FieldInfo* GetNewPointer() const {
			FieldInfo* new_ptr = NewPointer();
			new_ptr->SetField(value);
			/* Copy the position info */
			new_ptr->Set_nword(nword);
			new_ptr->Set_bitpos(bitpos);
			new_ptr->Set_endpos(endpos);
			new_ptr->field_set = field_set;
			return new_ptr;
		}

		/* Seters */
		void Set_nword(size_t _nword) { nword = _nword; };
		void Set_bitpos(size_t _bitpos) { bitpos = _bitpos; };
		void Set_endpos(size_t _endpos) { endpos = _endpos; };

		/* Geters */
		size_t Get_nword() const { return nword; };
		size_t Get_bitpos() const { return bitpos; };
		size_t Get_endpos() const { return endpos; };

		byte IsFieldSet() const { return field_set; };
		void FieldSetted() { field_set = 1; };
		void ResetField() { field_set = 0; };

		/* Print un human readable form */
		virtual void PrintField() const = 0;

		/* Clear field */
		virtual void Clear() = 0;

		virtual ~FieldInfo() { };
	};

	template<class T>
	class GeneralField : public FieldInfo {
	protected:
		T HumanValue;
	public:
		GeneralField(size_t _nword = 0, size_t _bitpos = 0, size_t _endpos = 0) {
			nword = _nword;
			bitpos = _bitpos;
			endpos = _endpos;
		};

		/* Print un human readable form */
		void PrintField() const = 0;

		/* Convert Human readable for to numeric form */
		virtual void HumanToNetwork(T _HumanValue) = 0;

		/* Set Human Value of the Field */
		virtual void SetField(word _value) = 0;

		/* Get a new pointer of a field with a copy of the data */
		FieldInfo* NewPointer() const = 0;

		/* Get value of the field */
		T GetHumanRead() const {return HumanValue;};

		/* Clear Value */
		void Clear() {value = 0; HumanValue = T();};

		virtual ~GeneralField() {};
	};

	template<class U, int N, int M>
	class BitField : public GeneralField<word> {
		/* Field Bit Packing */
		struct FieldPack {
			U fieldh:M, fieldl:N;
		} FieldValue;
		/* Names of the fields */
		std::string nameh;
		std::string namel;
	public:
		BitField(size_t _nword = 0, size_t _bitpos = 0, size_t _endpos = 0, const std::string& _namel="", const std::string& _nameh="") {
			/* Sanity Code */
			if ( (N+M) != (8 * sizeof(U)) || (N+M) > (8 * sizeof(word)) ) {
				std::cout << "[!] Field() :: Unable to create BitField with N = " << N << " and M = " << M << std::endl;
				std::cout << "[!] Field() :: The sum of M + N should be equal to " << 8 * sizeof(U) << std::endl;
				exit(1);
			} else {
				nword = _nword;
				bitpos = _bitpos;
				endpos = _endpos;

				/* Init field values */
				FieldValue.fieldh = 0;
				FieldValue.fieldl = 0;

				/* Set fields names */
				nameh = _nameh;
				namel = _namel;
			}
		};

		/* Field Setters */
		void SetHighField(U value) {
			FieldValue.fieldh = value;
		};

		void SetLowField(U value) {
			FieldValue.fieldl = value;
		};

		/* Field Getters */
		U GetHighField() const {
			return FieldValue.fieldh;
		};

		U GetLowField() const {
			return FieldValue.fieldl;
		};

		void HumanToNetwork(word DummyValue) {
			/* Ignore dummy value */
			U field_pack = 0;
			memcpy((void*)&field_pack,(const void*)&FieldValue,sizeof(FieldPack));
			/* Copy the entire pack to a word */
			value = field_pack;
		};

		/* Set Human Value of the Field */
		void SetField(word _value) {
			/* Copy the word */
			memcpy((void*)&FieldValue,(const void*)&_value,sizeof(FieldPack));
			value = _value;
		};

		FieldInfo* NewPointer() const {
			/* Create field */
			FieldInfo* new_ptr = new BitField;

			BitField* cast_ptr = dynamic_cast<BitField*>(new_ptr);

			/* Names of the fields */
			cast_ptr->nameh = nameh;
			cast_ptr->namel = namel;

			return new_ptr;
		}

		void PrintField() const {
			std::cout << "(" << namel << "=" << (word)FieldValue.fieldl << "," << nameh << "=" << (word)FieldValue.fieldh << ")";
		};

		virtual ~BitField() { };

	};

	class ControlFlags : public GeneralField<word> {
		static const std::string flags[];

	public:
		ControlFlags(size_t _nword = 0, size_t _bitpos = 0, size_t _endpos = 0) {
				nword = _nword;
				bitpos = _bitpos;
				endpos = _endpos;
		};

		void HumanToNetwork(word _HumanValue) {
			HumanValue  = _HumanValue;
			/* Convert from Human to Numeric form */
			value = HumanValue;
		};

		/* Set Human Value of the Field */
		void SetField(word _value) {
			/* Copy the word */
			HumanValue = _value;
			value = _value;
		};

		FieldInfo* NewPointer() const {
			/* Create field */
			FieldInfo* new_ptr = new ControlFlags;

			return new_ptr;
		}

		void PrintField() const {
			std::cout << "( ";

			for(int i = 0 ; i < 8 ; i++) {
				int flag_shift = 1 << i;

				if (flag_shift & value)
					std::cout << flags[i] << " ";
			}

			std::cout << ")";
		};

		virtual ~ControlFlags() { };

	};

	class NumericField : public GeneralField<word> {
	public:
		/* Construct Field */
		NumericField(size_t _nword = 0, size_t _bitpos = 0, size_t _endpos = 0) {
			nword = _nword;
			bitpos = _bitpos;
			endpos = _endpos;
			HumanValue = 0;
		};

		void HumanToNetwork(word _HumanValue) {
			HumanValue  = _HumanValue;
			/* Convert from Human to Numeric form */
			value = HumanValue;
		};

		/* Set Human Value of the Field */
		void SetField(word _value) {
			/* Copy the word */
			HumanValue = _value;
			value = _value;
		};

		FieldInfo* NewPointer() const {
			/* Create field */
			FieldInfo* new_ptr = new NumericField;

			return new_ptr;
		}

		void PrintField() const {std::cout << std::dec << HumanValue;};

		virtual ~NumericField() { };
	};

	class HexField : public GeneralField<word> {
	public:
		/* Construct Field */
		HexField(size_t _nword = 0, size_t _bitpos = 0, size_t _endpos = 0) {
			nword = _nword;
			bitpos = _bitpos;
			endpos = _endpos;
			HumanValue = 0;
		};

		void HumanToNetwork(word _HumanValue) {
			HumanValue  = _HumanValue;
			/* Convert from Human to Numeric form */
			value = HumanValue;
		};

		/* Set Human Value of the Field */
		void SetField(word _value) {
			/* Copy the word */
			HumanValue = _value;
			value = _value;
		};

		FieldInfo* NewPointer() const {
			/* Create field */
			FieldInfo* new_ptr = new HexField;

			return new_ptr;
		}

		void PrintField() const {std::cout << std::hex << "0x" << HumanValue;};

		virtual ~HexField () { };
	};

	class IPAddress : public GeneralField<std::string> {
	public:
		/* Construct Field */
		IPAddress(size_t _nword = 0, size_t _bitpos = 0, size_t _endpos = 0) {
			nword = _nword;
			bitpos = _bitpos;
			endpos = _endpos;
		};

		void HumanToNetwork(std::string _IPAddress) {
			if (_IPAddress.find_first_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIKKLMNOPQRSTUVWXYZ") != std::string::npos) {
				/* We should try to resolve the hostname */
				std::string ip_address = Crafter::GetIP(_IPAddress);

				if (ip_address.size() == 0)
					exit(1);

				/* Keep the first value */
				_IPAddress = ip_address;
			}

			HumanValue  = _IPAddress;
			/* Convert from Human to Numeric form */
			value = inet_network(HumanValue.c_str());
		};

		/* Set Human Value of the Field */
		void SetField(word _value) {
			/* Copy the word */
			value = _value;
			/* Get IP Address */
			struct in_addr local_address;
			local_address.s_addr = htonl(_value);
			std::string ip(inet_ntoa(local_address));
			HumanValue = ip;
		};

		FieldInfo* NewPointer() const {
			/* Create field */
			FieldInfo* new_ptr = new IPAddress;

			return new_ptr;
		}

		void PrintField() const {std::cout << HumanValue;};

		~IPAddress();
	};

}

#endif /* FIELD_H_ */
