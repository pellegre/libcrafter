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

#ifndef IPLAYER_H_
#define IPLAYER_H_

#include "../Layer.h"

namespace Crafter {

    class IPLayer: public Layer {

    public:

    	enum { PROTO = 0xfff6 };

        IPLayer() { /* Constructor */ };

        virtual void SetSourceIP(const std::string& value) = 0;

        virtual void SetDestinationIP(const std::string& value) = 0;

        virtual std::string  GetSourceIP() const = 0;

        virtual std::string  GetDestinationIP() const = 0;

        virtual byte* GetRawSourceIP() const = 0;
        
        virtual byte* GetRawDestinationIP() const = 0;
        
        /* Method to build IP layer from the source address */
        static IPLayer* BuildSrc(const std::string& ip_src);

        /* Method to build IP layer from the destination address */
        static IPLayer* BuildDst(const std::string& ip_dst);

        /*
         * Method to build IP layer from the destination address and set the correct IP
         * on the source field (from the interface specified).
         */
        static IPLayer* BuildDst(const std::string& ip_dst, const std::string& iface);

        virtual ~IPLayer() { /* Destructor */ };

    };

}

#endif /* IPLAYER_H_ */
