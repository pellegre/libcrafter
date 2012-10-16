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
byte ICMPLayer::DestinationUnreachable = 1;
byte ICMPLayer::TimeExceeded = 2;
byte ICMPLayer::ParameterProblem = 3;

/* +++ Request and replies +++ */
byte ICMPLayer::EchoRequest = 4;
byte ICMPLayer::EchoReply = 5;

ICMPLayer* ICMPLayer::Build(const std::string& ip_address, int icmp_type) {
	ICMPLayer* icmp_layer = 0;
	if(validateIpv4Address(ip_address)) icmp_layer = new ICMP();
	if(validateIpv6Address(ip_address)) icmp_layer = new ICMPv6();
	if(icmp_layer) icmp_layer->SetType(icmp_layer->MapTypeNumber(icmp_type));
	return icmp_layer;
}
