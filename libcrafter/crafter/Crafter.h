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

#ifndef CRAFTER_H_
#define CRAFTER_H_

/* Layer interface */
#include "Layer.h"

/* Ethernet Protocol Implementation */
#include "Protocols/Ethernet.h"

/* Dot1Q Protocol Implementation */
#include "Protocols/Dot1Q.h"

/* SLL Protocol Implementation */
#include "Protocols/SLL.h"

/* BSD loopback encapsulation Implementation */
#include "Protocols/NullLoopback.h"

/* Address Resolution Protocol Implementation */
#include "Protocols/ARP.h"

/* UDP Protocol Implementation */
#include "Protocols/UDP.h"

/* TCP Protocol Implementation */
#include "Protocols/TCP.h"
/* TCP Options Implementation */
#include "Protocols/TCPOptionLayer.h"
#include "Protocols/TCPOption.h"
#include "Protocols/TCPOptionMaxSegSize.h"
#include "Protocols/TCPOptionTimestamp.h"
#include "Protocols/TCPOptionWindowScale.h"
#include "Protocols/TCPOptionPad.h"
#include "Protocols/TCPOptionMPTCP.h"

/* IPv4 Protocol Implementation */
#include "Protocols/IP.h"
/* IPv4 options Implementation */
#include "Protocols/IPOptionLayer.h"
#include "Protocols/IPOption.h"
#include "Protocols/IPOptionPad.h"
#include "Protocols/IPOptionTraceroute.h"
#include "Protocols/IPOptionPointer.h"

/* IPv6 Protocol Implementation */
#include "Protocols/IPv6.h"
#include "Protocols/IPv6FragmentationHeader.h"
/* Routing Extension Header */
#include "Protocols/IPv6RoutingHeader.h"
#include "Protocols/IPv6SegmentRoutingHeader.h"
#include "Protocols/IPv6MobileRoutingHeader.h"

/* IMCP base class */
#include "Protocols/ICMPLayer.h"

/*ICMPv6 implementation */
#include "Protocols/ICMPv6Layer.h"
#include "Protocols/ICMPv6.h"

/* ICMP Protocol Implementation */
#include "Protocols/ICMP.h"

/* ICMPExtension Protocol Implementation */
#include "Protocols/ICMPExtension.h"

/* ICMPExtensionMPLS Protocol Implementation */
#include "Protocols/ICMPExtensionMPLS.h"

/* ICMPExtensionObject Protocol Implementation */
#include "Protocols/ICMPExtensionObject.h"

/* DNS Protocol Implementation */
#include "Protocols/DNS.h"

/* DHCP Protocol Implementation */
#include "Protocols/DHCP.h"

/* Raw Layer, nothing specific */
#include "Protocols/RawLayer.h"

/* Packet Manipulation class */
#include "Packet.h"

#endif /* CRAFTER_H_ */
