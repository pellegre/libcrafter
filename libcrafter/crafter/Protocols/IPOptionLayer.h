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

#ifndef IPOPTIONLAYER_H_
#define IPOPTIONLAYER_H_

#include "../Layer.h"

namespace Crafter {

    class IPOptionLayer: public Layer {

        void ParseLayerData(ParseInfo* info);

    public:

    	IPOptionLayer() { /* */ };

    	struct ExtraInfo {
    		/* Next layer on the top of the options */
    		Layer* next_layer;
    		/* Remaining option length */
    		int optlen;
    	};

        virtual void SetCopyFlag(const word& value) = 0;

        virtual void SetClass(const word& value) = 0 ;

        virtual void SetOption(const word& value) = 0;

        virtual void SetLength(const byte& value) = 0;

        virtual word  GetCopyFlag() const = 0;

        virtual word  GetClass() const = 0;

        virtual word  GetOption() const = 0;

        virtual byte  GetLength() const = 0;

        /* Build IP options from first byte */
        static IPOptionLayer* Build(int opt);

        ~IPOptionLayer() { /* Destructor */ };

    };

}


#endif /* IPOPTIONLAYER_H_ */
