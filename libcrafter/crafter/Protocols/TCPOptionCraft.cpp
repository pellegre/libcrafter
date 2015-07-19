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
	TCPOptionLayer::ExtraInfo* extra_info =
		static_cast<TCPOptionLayer::ExtraInfo*>(info->extra_info);
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
		info->next_layer = Build(opt, info);
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


#define EDO_HDRLEN_OFF 0
#define EDO_SEGLEN_OFF 2

const byte TCPOptionEDO::EDOREQUEST = 2;
const byte TCPOptionEDO::EDO = 4;
const byte TCPOptionEDO::EDOEXT = 6;


void TCPOptionEDO::UpdateLengths() {
	/* Reset the EDO payload */
	LayerPayload.Clear();

	if (GetLength() == TCPOptionEDO::EDOREQUEST)
		return;

	/* Get size up to the TCP Layer */
	Layer *bottom = GetBottomLayer();
    size_t bottom_len = GetLength();
    while (bottom && bottom->GetID() != TCP::PROTO) {
        bottom_len += static_cast<TCPOptionLayer*>(bottom)->GetLength();
		bottom = bottom->GetBottomLayer();
    }
	/* Get remaining option size towards top */
	Layer *top = GetTopLayer();
	size_t top_len = 0;
	while (top && (top->GetID() >> 8 == TCPOption::PROTO >> 8)) {
		top_len += static_cast<TCPOptionLayer*>(top)->GetLength();
		top = top->GetTopLayer();
	}

	/* Compute the actual tcp option len */
	header_length = 5 + (bottom_len + top_len) / 4;

	/* If we reached a TCP Header at some point, set its DataOffset */
	if (bottom && GetLength() != EDOREQUEST) {
		TCP *tcp = static_cast<TCP*>(bottom);
		tcp->SetDataOffset(5 + bottom_len/4);
	}

	/* Compute the tcp data segment size */
	segment_length = 0;
	while (top) {
		segment_length += top->GetSize();
		top = top->GetTopLayer();
	}

	short_word net_order = htons(header_length);
	AddPayload((byte*)&net_order, sizeof(net_order));
	if (GetLength() == TCPOptionEDO::EDOEXT) {
		net_order = htons(segment_length);
		AddPayload((byte*)&net_order, sizeof(net_order));
	}
}

void TCPOptionEDO::ParseLayerData(ParseInfo* info) {
#define EDO_READ_SHORT(info, off) \
    ntohs(*((short_word*)(info->raw_data + info->offset + off)))

	TCPOptionLayer::ExtraInfo* extra_info =
		static_cast<TCPOptionLayer::ExtraInfo*>(info->extra_info);
    if(!extra_info || GetLength() > extra_info->optlen) {
        PrintMessage(Crafter::PrintCodes::PrintWarning,
                    "TCPOptionEDO::ParseLayerData",
                    "ExtraInfo is inconsistent!");
        info->top = 1;
        return;
    }

	switch (GetLength()) {
		case TCPOptionEDO::EDOEXT:
			segment_length = EDO_READ_SHORT(info, EDO_SEGLEN_OFF);
                /* Fallthrough */
		case TCPOptionEDO::EDO: { /* HeaderLength is present */
                header_length = EDO_READ_SHORT(info, EDO_HDRLEN_OFF);
                /* We gained extra option space,
				 * take it into account for parsing */
				size_t increase = 4 * (header_length - extra_info->header_len);
                extra_info->optlen += increase;
                break;
			}
		default:
			break;
	}
    TCPOption::ParseLayerData(info);
#undef EDO_READ_SHORT
}

void TCPOptionEDO::PrintPayload(std::ostream& str) const {
	switch (GetLength()) {
		case EDOEXT: str << "SegmentLength=" << segment_length << " , ";
				/* Fallthrough */
		case EDO: str << "HeaderLength=" << header_length << " , ";
				break;
		default: break;
	}
}
