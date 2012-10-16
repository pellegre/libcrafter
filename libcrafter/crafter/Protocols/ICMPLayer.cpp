/*
 * ICMPLayer.cpp
 *
 *  Created on: Oct 15, 2012
 *      Author: larry
 */

#include "ICMPLayer.h"
#include "ICMP.h"
#include "ICMPv6.h"
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
