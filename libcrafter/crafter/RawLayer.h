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


#ifndef RAWLAYER_H_
#define RAWLAYER_H_

#include "Layer.h"

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

			void LibnetBuild(libnet_t *l);

		public:

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
			RawLayer& operator=(const Layer& layer);

			/* Concatenate to raw layers */
			const RawLayer operator+(const RawLayer& right) const;

			virtual ~RawLayer() { };
		};

}

#endif /* RAWLAYER_H_ */
