/*
 * ICMPLayer.h
 *
 *  Created on: Oct 15, 2012
 *      Author: larry
 */

#ifndef ICMPLAYER_H_
#define ICMPLAYER_H_

#include "../Layer.h"

namespace Crafter {

	class ICMPLayer: public Layer {
	public:
		ICMPLayer() {/* */};

        virtual void SetType(const byte& value) = 0;

        virtual void SetCode(const byte& value) = 0;

        virtual void SetCheckSum(const short_word& value) = 0;

        virtual void SetRestOfHeader(const word& value) = 0;

        virtual void SetIdentifier(const short_word& value) = 0;

        virtual void SetSequenceNumber(const short_word& value) = 0;

        virtual word  GetRestOfHeader() const = 0;

        virtual short_word  GetIdentifier() const = 0;

        virtual short_word  GetSequenceNumber() const = 0;

        virtual byte  GetType() const = 0;

        virtual byte  GetCode() const = 0;

        virtual short_word  GetCheckSum() const = 0;

		virtual ~ICMPLayer() {/* */};
	};

}
#endif /* ICMPLAYER_H_ */
