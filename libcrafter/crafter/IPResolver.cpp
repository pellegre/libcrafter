/*
Copyright (C) 2012 Pellegrino E.

This file is part of libcrafter

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/


#include "IPResolver.h"
#include "PrintMessage.h"

using namespace std;

string Crafter::GetIP(const string& hostname) {
    /* We shoukd make a DNS query */
    struct addrinfo hints, *res;
    struct in_addr addr;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;

    if ((err = getaddrinfo(hostname.c_str(), NULL, &hints, &res)) != 0) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "GetIP()","Error while resolving "+ hostname);
      return "";
    }

    /* Set the IP */
    addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;

    /* Get the IP address as a string */
    string ip_address (inet_ntoa(addr));

    freeaddrinfo(res);

    /* Return the address */
    return ip_address;
}

std::string Crafter::GetHostname(const std::string& ip_address) {
	/* Host and service name */
	char host[1024];
	char service[20];

	/* Fill the sa structure with IP information */
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
    sa.sin_port = htons(0);
    sa.sin_addr.s_addr = inet_addr(ip_address.c_str());
    memset(sa.sin_zero, '\0', sizeof(sa.sin_zero));

	/* Make the inverse lookup */
    getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), service, sizeof(service), 0);

    return string(host);
}
