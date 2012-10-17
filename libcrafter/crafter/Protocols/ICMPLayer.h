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
	protected:

		/* Map common type numbers to the derived class */
		virtual byte MapTypeNumber(short_word type) = 0;

	public:

		/* ------- Messages types common to ICMPv4 and ICMPv6 --------- */

		/* +++ Error messages +++ */
		static short_word DestinationUnreachable;
		static short_word TimeExceeded;
		static short_word ParameterProblem;

		/* +++ Request and replies +++ */
		static short_word EchoRequest;
		static short_word EchoReply;


		ICMPLayer() {/* */};

                bool IsType(short_word type) { return MapTypeNumber(type) == GetType(); }

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

        /* Layer builder */
        static ICMPLayer* Build(const std::string& ip_address, short_word icmp_type = 0);

		virtual ~ICMPLayer() {/* */};
	};

}
#endif /* ICMPLAYER_H_ */
