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

#include "RawLayer.h"

using namespace std;
using namespace Crafter;

RawLayer::RawLayer() {
	/* Name of the protocol */
	SetName("RawLayer");
	/* Set protocol Number */
	SetprotoID(0xfff1);

	DefineProtocol();
}


void RawLayer::LibnetBuild(libnet_t *l) {

	/* Get the payload */
	size_t payload_size = GetPayloadSize();
	byte* payload;
	if (payload_size) {
		payload = new byte[payload_size];
		GetPayload(payload);
	} else
		payload = 0;

	/* Now write the data into de libnet context */
	int pay = libnet_build_data	( payload,
								  payload_size,
								  l,
								  0
							    );

	/* In case of error */
	if (pay == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "RawLayer::LibnetBuild()",
		             "Unable to build RawData header: " + string(libnet_geterror (l)));
		exit (1);
	}

	if(payload)
		delete [] payload;
}

/* Constructor from raw data */
RawLayer::RawLayer(const byte* data, size_t size) {
	/* Name of the protocol */
	SetName("RawLayer");
	/* Set protocol Number */
	SetprotoID(0xfff1);

	DefineProtocol();

	SetPayload(data,size);
}

/* Constructor from string */
RawLayer::RawLayer(const char* str) {
	/* Name of the protocol */
	SetName("RawLayer");
	/* Set protocol Number */
	SetprotoID(0xfff1);

	DefineProtocol();

	SetPayload(str);
}

/* Constructor from a general Layer */
RawLayer::RawLayer(const Layer& layer){
	/* Name of the protocol */
	SetName("RawLayer");
	/* Set protocol Number */
	SetprotoID(0xfff1);

	DefineProtocol();

	/* Get the size of the layer */
	size_t layer_size = layer.GetSize();
	/* Allocate memory */
	byte* data = new byte[layer_size];

	/* Put data into the buffer */
	layer.GetRawData(data);

	/* Now, set the payload */
	SetPayload(data,layer_size);

	delete [] data;
}

/* Equal from string */
RawLayer& RawLayer::operator=(const char* str) {
	SetPayload(str);
	return *this;
}

/* Equal from a general Layer */
RawLayer& RawLayer::operator=(const Layer& layer) {
	/* Get the size of the layer */
	size_t layer_size = layer.GetSize();
	/* Allocate memory */
	byte* data = new byte[layer_size];

	/* Put data into the buffer */
	layer.GetRawData(data);

	/* Now, set the payload */
	SetPayload(data,layer_size);

	delete [] data;

	return *this;
}

const RawLayer RawLayer::operator+(const RawLayer& right) const{
	/* Get both size */
	size_t right_size = right.GetSize();
	size_t left_size = GetSize();

	/* Allocate buffer */
	byte* buffer = new byte[right_size + left_size];

	/* Get data */
	size_t copied = GetRawData(buffer);
	right.GetRawData(buffer + copied);

	RawLayer ret_layer = RawLayer(buffer, right_size + left_size);

	delete [] buffer;

	return ret_layer;
}
