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


#ifndef PRINTMESSAGE_H_
#define PRINTMESSAGE_H_

#include <iostream>
#include <string>
#include <cstdio>
#include <stdint.h>

typedef uint8_t byte;

namespace Crafter {

	namespace PrintCodes {
		const uint16_t PrintMessage = 0;
		const uint16_t PrintWarning = 1;
		const uint16_t PrintError = 2;
		const uint16_t PrintPerror = 3;
	}

	/* Return a string with a message from some routine o the library */
	void PrintMessage(uint16_t code, const std::string& routine, const std::string& message = "");
}


#endif /* PRINTMESSAGE_H_ */
