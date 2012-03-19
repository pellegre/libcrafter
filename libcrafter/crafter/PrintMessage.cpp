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


#include "PrintMessage.h"

using namespace std;
using namespace Crafter;

namespace Crafter {
	extern /* Verbose mode flag */
	byte ShowWarnings;
}

void Crafter::PrintMessage(uint16_t code, const string& routine, const string& message) {
	string code_str;

	switch(code) {
		/* Just print some message */
		case PrintCodes::PrintMessage :
			code_str = "[@] MESSAGE ";
			break;

	    /* Print a warning */
		case PrintCodes::PrintWarning :
			code_str = "[!] WARNING ";
			break;

		/* Print the error message */
		case PrintCodes::PrintError :
			code_str = "[!] ERROR ";
			break;
		case PrintCodes::PrintPerror :
			code_str = "[!] ERROR ";
			break;

		default:
			code_str = "";
			break;

	}

	/* Print String */
	string ret_str = code_str + " : " + routine + " -> " + message;

	/* Check if we should use the perror routine */
	if (code == PrintCodes::PrintPerror) {
		perror(ret_str.c_str());
		return;
	}

	if(code == PrintCodes::PrintMessage) {
		cout << ret_str << endl;
		return;
	} else if (code == PrintCodes::PrintWarning) {
		if(ShowWarnings)
			cerr << ret_str << endl;
		return;
	} else {
		cerr << ret_str << endl;
		return;
	}
}

