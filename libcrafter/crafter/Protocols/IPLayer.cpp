/*
 * IPLayer.cpp
 *
 *  Created on: Jun 23, 2012
 *      Author: larry
 */

#include "IPLayer.h"
#include "IP.h"
#include "IPv6.h"
#include "../Utils/IPResolver.h"

using namespace Crafter;

/* Method to build IP layer from the source address */
IPLayer* Crafter::IPLayer::BuildSrc(const std::string& ip_src) {
	IPLayer* ip_layer = 0;
	if(validateIpv4Address(ip_src)) ip_layer = new IP();
	if(validateIpv6Address(ip_src)) ip_layer = new IPv6();
	if(ip_layer) ip_layer->SetSourceIP(ip_src);
	return ip_layer;
}

/* Method to build IP layer from the destination address */
IPLayer* Crafter::IPLayer::BuildDst(const std::string& ip_dst) {
	IPLayer* ip_layer = 0;
	if(validateIpv4Address(ip_dst)) ip_layer = new IP();
	if(validateIpv6Address(ip_dst)) ip_layer = new IPv6();
	if(ip_layer) ip_layer->SetDestinationIP(ip_dst);
	return ip_layer;
}

