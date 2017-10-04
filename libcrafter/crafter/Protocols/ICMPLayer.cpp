/*
 * ICMPLayer.cpp
 *
 *  Created on: Oct 15, 2012
 *      Author: larry
 */

#include "ICMPLayer.h"
#include "ICMP.h"
#include "ICMPv6.h"
#include "ICMPExtension.h"
#include "RawLayer.h"
#include "../Utils/IPResolver.h"

using namespace Crafter;

/* ------- Messages types --------- */

/* +++ Error messages +++ */
short_word ICMPLayer::DestinationUnreachable = 1000;
short_word ICMPLayer::TimeExceeded = 1001;
short_word ICMPLayer::ParameterProblem = 1002;

/* +++ Request and replies +++ */
short_word ICMPLayer::EchoRequest = 1003;
short_word ICMPLayer::EchoReply = 1004;

ICMPLayer* ICMPLayer::Build(const std::string& ip_address, short_word icmp_type) {
	ICMPLayer* icmp_layer = 0;
	if(validateIpv4Address(ip_address)) icmp_layer = new ICMP();
	if(validateIpv6Address(ip_address)) icmp_layer = new ICMPv6();
	if(icmp_layer) icmp_layer->SetType(icmp_layer->MapTypeNumber(icmp_type));
	return icmp_layer;
}

void ICMPLayer::parseExtensionHeader(ParseInfo *info, word payload_len)
{
	/* See RFC 4884 */
	word length = info->total_size - info->offset;

	if (payload_len == 0) {
		/* If the length attribute is zero, the compliant application
		 * MUST determine that the message contains no extensions.
		 * [...]
		 * it will parse for a valid extension  header at a fixed location,
		 * assuming a 128-octet "original datagram" field.
		 * If the application detects a valid version and checksum, it
		 * will treat the octets that follow as an extension structure.*/
		payload_len = length;
		if (payload_len >= 144 - 8) {
			/* The 144-octet sum is derived from 8 octets for the first two
			 * words of the ICMPv4 Time Exceeded message, 128 octets for
			 * the "original datagram" field, 4 octets for the ICMP
			 * Extension Header, and 4 octets for a single ICMP Object
			 * header.  All of these octets would be required if extensions
			 * were present.
			 * BUT info->offset already accounts for the 8 octets for the
			 * first two words of the ICMP message, hence the substraction. */
			byte *ext_hdr = (byte *)(info->raw_data + info->offset + 128);
			byte version = (*ext_hdr) >> 4;
			/* Checksum: 16 bits. The one's complement of the one's
			 * complement sum of the data structure, with the checksum
			 * field replaced by zero for the purpose of computing the
			 * checksum.*/
			short_word *csum_loc = (short_word *)(ext_hdr + 2);
			short_word o_csum = *csum_loc;
			*csum_loc = 0;
			/* Extension headers/objects MUST be 32b aligned,
			 * i.e. length - 128 / 2 is the _exact_ number of 16b words */
			short_word csum = CheckSum((short_word *)ext_hdr, (length - 128) / 2);
			*csum_loc = o_csum;
			/* Check if we have the right extension version and checksum,
			 * a checksum of 0 indicates that no checksum was set. */
			if (version == 2 && (!o_csum || csum == o_csum))
				payload_len = 128;
		}
	} else {
		/* The length field represents the actual size of the original
		 * datagram. BUT if the message contains extensions, it MUST pad
		 * this embed to the nearset 32b boundary, such that the payload is
		 * at least 128b. */
		if (payload_len < length) {
			/* There is additional data, maybe an ICMP extension,
			 * follow the padding rules */
			if (payload_len < 128)
				payload_len = 128;
			else if (payload_len % 4)
				payload_len += 4 - (payload_len % 4);
		}
	}
	if (payload_len > length) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				"Inconsistent ICMP length wrt. its received size");
		payload_len = length;
	}
	/* Set the next layer as a RawLayer  (sandwich layer) */
	info->next_layer = Protocol::AccessFactory()->GetLayerByID(RawLayer::PROTO);
	info->extra_info = new RawLayer::ExtraInfo(
			info->raw_data + info->offset, payload_len,
			(payload_len >= length) ? NULL : /* Is there any extension? */
			Protocol::AccessFactory()->GetLayerByID(ICMPExtension::PROTO));
}
