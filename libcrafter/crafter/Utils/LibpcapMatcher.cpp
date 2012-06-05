/*
 * LibpcapMatcher.cpp
 *
 *  Created on: Jun 5, 2012
 *      Author: larry
 */

#include "LibpcapMatcher.h"
#include "../Utils/PrintMessage.h"

using namespace std;
using namespace Crafter;

Crafter::LibpcapMatcher::LibpcapMatcher(const std::string& iface, int timeout) : device(iface), timeout(timeout) {

	/* Set error buffer to 0 length string to check for warnings */
	errbuf[0] = 0;

	/* Open device for sniffing */
	handle = pcap_open_live (device.c_str(),  /* device to sniff on */
						     BUFSIZ,          /* maximum number of bytes to capture per packet */
									          /* BUFSIZE is defined in pcap.h */
						     1,               /* promisc - 1 to set card in promiscuous mode, 0 to not */
						     timeout*1000,    /* to_ms - amount of time to perform packet capture in milliseconds */
									          /* 0 = sniff until error */
						     errbuf);         /* error message buffer if something goes wrong */

	if (handle == NULL) {
		/* There was an error */
		PrintMessage(Crafter::PrintCodes::PrintError,
					 "LibpcapMatcher::LibpcapMatcher()",
					 "opening the libpcap handler: " + string(errbuf));
		exit (1);
	}

	if (strlen (errbuf) > 0) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
					"LibpcapMatcher::LibpcapMatcher()",
					string(errbuf));
		errbuf[0] = 0;    /* re-set error buffer */
	}

	/* Find out the datalink type of the connection */
	link_type = pcap_datalink(handle);

	/* Get the IP subnet mask of the device, so we set a filter on it */
	if (pcap_lookupnet (device.c_str(), &netp, &maskp, errbuf) == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "LibpcapMatcher::LibpcapMatcher()",
                     "Looking net parameters: " + string(errbuf));
		exit (1);
	}

}


LibpcapMatcher::~LibpcapMatcher() { /* */ }

