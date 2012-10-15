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

#include "IPLayer.h"
#include "IP.h"
#include "IPv6.h"
#include "../Utils/IPResolver.h"

using namespace std;
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

static IPLayer* Crafter::IPLayer::BuildDst(const std::string& ip_dst, const std::string& iface) {
	IPLayer* ip_layer = 0;
	string ip_src = "";
	if(validateIpv4Address(ip_dst)) {
		ip_layer = new IP();
		ip_src = GetMyIP(iface);
	}
	if(validateIpv6Address(ip_dst)) {
		ip_layer = new IPv6();
		ip_src = GetMyIPv6(iface);
	}
	if(ip_layer) {
		ip_layer->SetDestinationIP(ip_dst);
		ip_layer->SetSourceIP(ip_src);
	}
	return ip_layer;
}
