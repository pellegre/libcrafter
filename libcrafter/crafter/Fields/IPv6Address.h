/*
 * IPv6Address.h
 *
 *  Created on: Jun 6, 2012
 *      Author: larry
 */

#ifndef IPV6ADDRESS_H_
#define IPV6ADDRESS_H_

#include <iostream>
#include <ostream>
#include <string>
#include "FieldInfo.h"

namespace Crafter {

	class IPv6Address : public Field<std::string> {

		size_t nword;
		size_t nbyte;
		size_t offset;

		void Print(std::ostream& str) const;

	public:

		IPv6Address(const std::string& name, size_t nword, size_t nbyte);

		void Write(byte* raw_data) const;

		void Read(const byte* raw_data);

		void SetField(const std::string& ip_address);

		FieldInfo* Clone() const;

		virtual ~IPv6Address();
	};

}

#endif /* IPV6ADDRESS_H_ */
