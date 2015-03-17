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


#include "IPResolver.h"
#include "PrintMessage.h"

using namespace std;

/* Validate IPv4 address */
bool Crafter::validateIpv4Address(const std::string& ipAddress) {
	struct in_addr addr;
	return inet_pton(AF_INET, ipAddress.c_str(), &addr);
}

/* Validate IPv6 address */
bool Crafter::validateIpv6Address(const std::string& ipAddress) {
	struct in6_addr addr;
	return inet_pton(AF_INET6, ipAddress.c_str(), &addr);
}

int Crafter::GetAddress(const string &hostname, string &result, int ai_family) {
	struct addrinfo hints, *rp;
	int err;
	/* Attempt to resolve the hostname */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ai_family;
	err = getaddrinfo(hostname.c_str(), NULL, &hints, &rp);
	if (err)
		return err;
	/* Convert IP to textual, numeric form */
	char addr[NI_MAXHOST];
	getnameinfo(rp->ai_addr, rp->ai_addrlen, addr,
			sizeof(addr), NULL, 0, NI_NUMERICHOST);
	freeaddrinfo(rp);
	result = addr;
	return 0;
}

string Crafter::GetIP(const string& hostname) {
    string r;
	if (GetAddress(hostname, r, AF_INET))
		PrintMessage(Crafter::PrintCodes::PrintWarningPerror,
				     "GetIPv4()","Error while resolving "+ hostname);
	return r;
}

string Crafter::GetIPv6(const string& hostname) {
    string r;
	if (GetAddress(hostname, r, AF_INET6))
		PrintMessage(Crafter::PrintCodes::PrintWarningPerror,
				     "GetIPv6()","Error while resolving "+ hostname);
	return r;
}

std::string Crafter::GetHostname(const std::string& ip_address) {
	struct addrinfo hints, *rp;
	int err;
	/* Get a sockaddr */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	err = getaddrinfo(ip_address.c_str(), NULL, &hints, &rp);
	if (err)
		return ip_address;
	/* Make the inverse lookup */
	char addr[NI_MAXHOST];
	if (getnameinfo(rp->ai_addr, rp->ai_addrlen, addr, sizeof(addr), NULL, 0, 0))
		return ip_address;
	freeaddrinfo(rp);
	return string(addr);
}
