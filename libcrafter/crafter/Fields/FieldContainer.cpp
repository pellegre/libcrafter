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

#include "FieldContainer.h"

using namespace std;
using namespace Crafter;

FieldContainer::FieldContainer() {
	/* By default, there aren't overlapped fields */
	overlaped_flag = 0;
}

FieldContainer::FieldContainer(const FieldContainer& fc) {
	const_iterator it;

	overlaped_flag = fc.overlaped_flag;
	ActiveFields = fc.ActiveFields;

	/* Clone each field of the container */
	for(it = fc.begin() ; it < fc.end() ; it++)
		push_back((*it)->CloneField());
}

void FieldContainer::SetActive(size_t nfield) {
	std::set<size_t> OverlappedFields;

	/* Get the field pointer */
	FieldInfo* ptr = (*this)[nfield];

	/* First, check if the field is active */
	if(ActiveFields.find(nfield) == ActiveFields.end()) {
		/* If the field is not active, it may overlap some other field */
		std::set<size_t>::iterator it_active;

		for (it_active = ActiveFields.begin() ; it_active != ActiveFields.end() ; ++it_active) {
			FieldInfo* FieldPtr = (*this)[(*it_active)];
			/* Get information of the active fields */
			size_t nword = FieldPtr->GetWord();

			/* Check if the fields are in the same word */
			if (ptr->GetWord() == nword) {
				size_t bitpos = FieldPtr->GetBit();
				size_t endpos = FieldPtr->GetEnd();

				/* Check intersection */
				if  ( ( (ptr->GetBit() >= bitpos) && (ptr->GetBit() < endpos) ) ||
					  ( (ptr->GetEnd() >  bitpos) && (ptr->GetEnd() <= endpos) )  ) {
					OverlappedFields.insert(*it_active);
				}

			}
		}
		/* And push it into the active fields set */
		ActiveFields.insert(nfield);
	}

	/* Remove overlapped fields, if any */
	std::set<size_t>::iterator it_over;

	for (it_over = OverlappedFields.begin() ; it_over != OverlappedFields.end() ; ++it_over)
		ActiveFields.erase(*it_over);

}

FieldContainer& FieldContainer::operator=(const FieldContainer& right) {
	const_iterator it;

	/* Delete each field of the container */
	for(it = begin() ; it < end() ; it++)
		delete (*it);

	clear();

	/* Clone each field of the container */
	for(it = right.begin() ; it < right.end() ; it++)
		push_back((*it)->CloneField());

	overlaped_flag = right.overlaped_flag;
	ActiveFields = right.ActiveFields;

	return *this;
}

FieldContainer::~FieldContainer() {
	iterator it;

	/* Delete each field of the container */
	for(it = begin() ; it < end() ; it++)
		delete (*it);
}

void FieldContainer::Print(std::ostream& str) const {
	if(!overlaped_flag) {
		const_iterator it;

		/* Delete each field of the container */
		for(it = begin() ; it < end() ; it++)
			str << *(*it) << " , ";

	} else {
		/* Just apply the function to the active fields */
		set<size_t>::const_iterator it_active;

		for (it_active = ActiveFields.begin() ; it_active != ActiveFields.end(); ++it_active)
			str << *(*this)[*it_active] << " , ";
	}

}
