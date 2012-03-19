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


#ifndef IPRESOLVER_H_
#define IPRESOLVER_H_

#include <iostream>
#include <string>
#include <map>
#include <cstring>
#include <cstdlib>
#include <cerrno>

#include <fcntl.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/poll.h>

namespace Crafter {
	/* Return IP from a host address */
	std::string GetIP(const std::string& hostname);

	/* Return the hostname of associated to the IP address */
	std::string GetHostname(const std::string& ip_address);
}

#endif /* IPRESOLVER_H_ */
