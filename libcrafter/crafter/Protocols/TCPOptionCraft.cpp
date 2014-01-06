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

#include "TCPOption.h"

using namespace Crafter;
using namespace std;

void TCPOption::ReDefineActiveFields() {
}

void TCPOption::Craft() {
	if(!IsFieldSet(FieldLength)) {
		SetLength(2 + GetPayloadSize());
		ResetField(FieldLength);
	}
}

void TCPOption::ParseLayerData(ParseInfo* info) {
	/* Update the information of the IP options */
	TCPOptionLayer::ExtraInfo* extra_info = reinterpret_cast<TCPOptionLayer::ExtraInfo*>(info->extra_info);
	if(!extra_info) {
		info->top = 1;
		return;
	}

	int optlen = GetLength();
	if(optlen > extra_info->optlen) optlen = extra_info->optlen;
	if(optlen > 2) {
		SetPayload(info->raw_data + info->offset, optlen - 2);
		info->offset += optlen - 2;
	}
	extra_info->optlen -= GetSize();
	if(extra_info->optlen > 0) {
		/* Get the option type */
		int opt = (info->raw_data + info->offset)[0];
		info->next_layer = Build(opt);
	}  else {
		info->next_layer = extra_info->next_layer;
		delete extra_info;
		extra_info = 0;
	}
}

void TCPOptionSACK::PrintPayload(ostream& str) const {
	cout << "Payload = ";

	vector<Pair> blocks = GetBlocks();
	vector<Pair>::iterator it_block = blocks.begin();

	for( ; it_block != blocks.end() - 1; it_block++) {
		(*it_block).Print(str);
		str << " , ";
	}
	(*it_block).Print(str);
	str << " ";
}

vector<TCPOptionSACK::Pair> TCPOptionSACK::GetBlocks() const {
	/* Get payload */
	size_t payload_size = GetPayloadSize();
	if( payload_size > 0) {
		const byte* raw_data = GetPayload().GetRawPointer();
		/* Cast to 32 bit numbers */
		const word* edges = (const word *)(raw_data);

		/* Container of blocks */
		vector<Pair> blocks;
		for(size_t i = 0 ; i < (2 * (payload_size/2))/sizeof(word) ; i += 2)
			blocks.push_back(Pair(ntohl(edges[i]),ntohl(edges[i+1])));

		return blocks;
	}

	return vector<TCPOptionSACK::Pair>();
}

void TCPOptionSACK::SetBlocks(const std::vector<TCPOptionSACK::Pair>& blocks) {
	/* First allocate space for the numbers */
	word* blocks_data = new word[blocks.size() * 2];

	vector<TCPOptionSACK::Pair>::const_iterator it_block = blocks.begin();

	size_t index = 0;
	for(; it_block != blocks.end() ; it_block++) {
		blocks_data[index] = htonl((*it_block).left);
		blocks_data[index + 1] = htonl((*it_block).right);
		index += 2;
	}

	/* Finally, set the payload with the data */
	SetPayload((const byte*)blocks_data,blocks.size()*2*sizeof(word));
	delete[] blocks_data;
}

void TCPOptionSACK::Pair::Print(ostream& str) const {
	str << left << "-" << right;
}

