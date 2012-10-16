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


#ifndef RAWLAYER_H_
#define RAWLAYER_H_

#include "../Layer.h"

namespace Crafter {

		class RawLayer : public Layer {

			/* Define the field of the IP layer */
			void DefineProtocol() {
				/* No fields */
			};

			Constructor GetConstructor() const {
				return RawLayer::RawLayerConstFunc;
			};

			static Layer* RawLayerConstFunc() {
				return new RawLayer;
			};

			/* Copy crafted packet to buffer_data */
			void Craft () {
				/* Nothing to craft */
			};

			void ParseLayerData(ParseInfo* info);

		public:

			struct ExtraInfo {
				/* Data */
				const byte* raw_data;
				/* Number of bytes to push on the RawLayer payload */
				size_t nbytes;
				/* Next layer */
				Layer* next_layer;

				ExtraInfo(const byte* raw_data, size_t nbytes, Layer* next_layer) :
				          raw_data(raw_data), nbytes(nbytes), next_layer(next_layer) {};
			};

			enum { PROTO = 0xfff1 };

			RawLayer();

			/* Constructor from raw data */
			RawLayer(const byte* data, size_t size);

			/* Constructor from string */
			RawLayer(const char* str);

			/* Constructor from a general Layer */
			RawLayer(const Layer& layer);

			/* Equal from string */
			RawLayer& operator=(const char* str);

			/* Equal from a general Layer */
			RawLayer& operator=(const Layer& layer) throw ();

			/* Concatenate to raw layers */
			const RawLayer operator+(const RawLayer& right) const;

			virtual ~RawLayer() { };
		};

		class Pad : public RawLayer {

		public:
			Pad(byte value, size_t times);
			~Pad() { /* */ };
		};

}

#endif /* RAWLAYER_H_ */
