/*
 * TCPOptionLayer.h
 *
 *  Created on: Jun 8, 2012
 *      Author: larry
 */

#ifndef TCPOPTIONLAYER_H_
#define TCPOPTIONLAYER_H_

#include "../Layer.h"

namespace Crafter {

    class TCPOptionLayer: public Layer {

    public:

        TCPOptionLayer() { /* */ };

        virtual void SetKind(const byte& value) = 0;

        virtual void SetLength(const byte& value) = 0;

        virtual byte  GetKind() const = 0;

        virtual byte  GetLength() const = 0;

        ~TCPOptionLayer() { /* Destructor */ };

    };

}


#endif /* TCPOPTIONLAYER_H_ */
