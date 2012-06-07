/*
 * IPLayer.h
 *
 *  Created on: Jun 7, 2012
 *      Author: larry
 */

#ifndef IPLAYER_H_
#define IPLAYER_H_

#include "../Layer.h"

namespace Crafter {

    class IPLayer: public Layer {

    public:

        IPLayer() { /* Constructor */ };

        virtual void SetSourceIP(const std::string& value) = 0;

        virtual void SetDestinationIP(const std::string& value) = 0;

        virtual std::string  GetSourceIP() const = 0;

        virtual std::string  GetDestinationIP() const = 0;

        virtual ~IPLayer() { /* Destructor */ };

    };

}

#endif /* IPLAYER_H_ */
