/*
 * IPOptionLayer.h
 *
 *  Created on: Jun 11, 2012
 *      Author: larry
 */

#ifndef IPOPTIONLAYER_H_
#define IPOPTIONLAYER_H_

#include "../Layer.h"

namespace Crafter {

    class IPOptionLayer: public Layer {

    public:

    	IPOptionLayer() { /* */ };

        virtual void SetCopyFlag(const word& value) = 0;

        virtual void SetClass(const word& value) = 0 ;

        virtual void SetOption(const word& value) = 0;

        virtual void SetLength(const byte& value) = 0;

        virtual word  GetCopyFlag() const = 0;

        virtual word  GetClass() const = 0;

        virtual word  GetOption() const = 0;

        virtual byte  GetLength() const = 0;

        ~IPOptionLayer() { /* Destructor */ };

    };

}


#endif /* IPOPTIONLAYER_H_ */
