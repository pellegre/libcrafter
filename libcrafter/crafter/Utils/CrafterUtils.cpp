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

#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#ifdef __APPLE__
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#include <net/if.h>

#include "../Crafter.h"
#include "CrafterUtils.h"

#include "IPv4Parse.h"
#include "IPResolver.h"

using namespace Crafter;
using namespace std;

string Crafter::GetMyMAC(const string& iface) {
#ifdef SIOCGIFHWADDR
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, iface.c_str());

	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		struct ether_addr ptr;
		memcpy(&ptr,s.ifr_addr.sa_data,sizeof(struct ether_addr));
		char buf[19];
		sprintf (buf, "%02x:%02x:%02x:%02x:%02x:%02x",
			  ptr.ether_addr_octet[0], ptr.ether_addr_octet[1],
			  ptr.ether_addr_octet[2], ptr.ether_addr_octet[3],
			  ptr.ether_addr_octet[4], ptr.ether_addr_octet[5]);
		buf[18] = 0;
		close(fd);
		return string(buf);

	} else {

		close(fd);
		return "";

	}
#else
	struct ifaddrs *ifa = NULL;
	getifaddrs(&ifa);

	while (ifa != NULL) {
		struct sockaddr_dl* dl = (struct sockaddr_dl*)ifa->ifa_addr;

		if (ifa->ifa_addr->sa_family == AF_LINK &&
		    dl->sdl_type == IFT_ETHER &&
		    !strcmp(ifa->ifa_name, iface.c_str())) {
			struct ether_addr ptr;
			memcpy(&ptr, &dl->sdl_data[dl->sdl_nlen], sizeof(struct ether_addr));
			char buf[19];
			sprintf (buf, "%02x:%02x:%02x:%02x:%02x:%02x",
				 ptr.ether_addr_octet[0], ptr.ether_addr_octet[1],
				 ptr.ether_addr_octet[2], ptr.ether_addr_octet[3],
				 ptr.ether_addr_octet[4], ptr.ether_addr_octet[5]);
			buf[18] = 0;
			return string(buf);
		}
		ifa = ifa->ifa_next;
	}
	return "";
#endif
}

string Crafter::GetMyIP(const string& iface) {
    struct ifaddrs* ifAddrStruct = 0;
    struct ifaddrs* ifa = 0;
    void* tmpAddrPtr = 0;
    /* Return value */
    string ret = "";

    if (getifaddrs(&ifAddrStruct) == -1)
		throw std::runtime_error("GetMyIP() : Unable to get interface information.");

    for (ifa = ifAddrStruct; ifa != 0; ifa = ifa->ifa_next) {

    	/* Check if is a IPv4 */
        if ( (ifa->ifa_addr) && ifa->ifa_addr->sa_family==AF_INET) {
        	/* Check the interface */
        	if(string(ifa->ifa_name).find(iface) != string::npos) {
            	/* Is a valid IP6 Address */
                tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                ret = string(addressBuffer);
                break;
        	}
        }

    }

    if (ifAddrStruct!=0) freeifaddrs(ifAddrStruct);

    return ret;
}

string Crafter::GetMyIPv6(const string& iface, bool ll) {
    struct ifaddrs* ifAddrStruct = 0;
    struct ifaddrs* ifa = 0;
    void* tmpAddrPtr = 0;
    /* Return value */
    string ret = "";

    if (getifaddrs(&ifAddrStruct) == -1)
		throw std::runtime_error("GetMyIP() : Unable to get interface information.");

    for (ifa = ifAddrStruct; ifa != 0; ifa = ifa->ifa_next) {

    	/* Check if is a IPv6 */
        if ( (ifa->ifa_addr) && ifa->ifa_addr->sa_family==AF_INET6) {
        	/* Check the interface */
        	if(string(ifa->ifa_name).find(iface) != string::npos) {
            	/* Is a valid IP6 Address */
                tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
                if (!ll && IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)tmpAddrPtr))
                        continue;
                char addressBuffer[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
                ret = string(addressBuffer);
                break;
        	}
        }

    }

    if (ifAddrStruct!=0) freeifaddrs(ifAddrStruct);

    return ret;
}

static const std::string GetMACIPv4(const std::string& IPAddress, const string& iface) {
	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	/* Get the MAC Address associated to the interface */
	string MyMAC = GetMyMAC(iface);
	/* Create the Ethernet layer */
	Ethernet ether_layer;

	/* Set source MAC */
	ether_layer.SetSourceMAC(MyMAC);
	/* Set broadcast destination address */
	ether_layer.SetDestinationMAC("ff:ff:ff:ff:ff:ff");

	/* Create the ARP layer */
	ARP arp_layer;

	/* We want an ARP request */
	arp_layer.SetOperation(ARP::Request);
	arp_layer.SetSenderIP(MyIP);
	arp_layer.SetSenderMAC(MyMAC);
	/* Set the target IP address */
	arp_layer.SetTargetIP(IPAddress);

	/* Create the packet */
	Packet arp_request;

	/* Push layers */
	arp_request.PushLayer(ether_layer);
	arp_request.PushLayer(arp_layer);

	/* Send the request and wait for an answer */
	Packet* arp_reply = arp_request.SendRecv(iface,2,3);

	/* Check if we receive an answer */
	if (arp_reply) {
		ARP* arp_reply_layer = GetARP(*arp_reply);
		if (arp_reply_layer) {
			string MAC = arp_reply_layer->GetSenderMAC();
			delete arp_reply;
			return MAC;
		}
		else {
			return "";
		}
	}

	return "";
}

const std::string GetMACIPv6(const std::string& IPAddress, const string& iface) {
	byte buf[sizeof(struct in6_addr)];
	inet_pton(AF_INET6, IPAddress.c_str(), buf);
	char mac[19];
	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", buf[8]^(1 << 1), buf[9], buf[10], buf[13], buf[14], buf[15]);
	mac[18] = 0;
	return string(mac);
}

const std::string Crafter::GetMAC(const std::string& IPAddress, const string& iface) {
	if(validateIpv4Address(IPAddress)) return GetMACIPv4(IPAddress,iface);
	if(validateIpv6Address(IPAddress)) return GetMACIPv6(IPAddress,iface);
	return "";
}

/* Parse ports defined by an interval and push the values into the set */
static void ParseNumbersInt(const string& argv, set<int>* port_values) {
	/* Check if there is an interval in the comma separated value */
	size_t middle = argv.find_first_of("-",0);

	if(middle != string::npos) {

		/* Get both numbers */
		string left = argv.substr(0,middle);
		string right = argv.substr(middle+1);

		/* Convert the string to integers */
		int nleft = atoi(left.c_str());
		int nright = atoi(right.c_str());

		/* Insert each value into the set */
		for(int i = nleft ; i <= nright ; i++)
			port_values->insert(i);

	}else {

		/* Is just one value */
		int value = atoi(argv.c_str());
		port_values->insert(value);

	}

}

vector<int>* Crafter::ParseNumbers(const string& argv) {
	/* Container of integer */
	vector<int>* ports = new vector<int>;

	/* Set of values */
	set<int> port_values;

	/* Position of comma separated values */
	size_t ini = 0;
	size_t end = argv.find_first_of(",",ini);

	/* Value between commas */
	string port_comma = argv.substr(ini,end-ini);

	ParseNumbersInt(port_comma,&port_values);

	while(end != string::npos) {
		/* Update position */
		ini = end + 1;
		/* Update value between commas */
		end = argv.find_first_of(",",ini);
		port_comma = argv.substr(ini,end-ini);

		ParseNumbersInt(port_comma,&port_values);
	}

	/* Put the values on the set into the vector */
	set<int>::iterator it_values;

	for(it_values = port_values.begin() ; it_values != port_values.end() ; it_values++)
		ports->push_back((*it_values));

	return ports;
}

vector<int> Crafter::GetNumbers(const string& argv) {
	/* Container of integer */
	vector<int> ports;

	/* Set of values */
	set<int> port_values;

	/* Position of comma separated values */
	size_t ini = 0;
	size_t end = argv.find_first_of(",",ini);

	/* Value between commas */
	string port_comma = argv.substr(ini,end-ini);

	ParseNumbersInt(port_comma,&port_values);

	while(end != string::npos) {
		/* Update position */
		ini = end + 1;
		/* Update value between commas */
		end = argv.find_first_of(",",ini);
		port_comma = argv.substr(ini,end-ini);

		ParseNumbersInt(port_comma,&port_values);
	}

	/* Put the values on the set into the vector */
	set<int>::iterator it_values;

	for(it_values = port_values.begin() ; it_values != port_values.end() ; it_values++)
		ports.push_back((*it_values));

	return ports;
}

string Crafter::StrPort(short_word port_number) {
	char* str_port = new char[6];
	sprintf(str_port,"%d", port_number);
	string ret_string(str_port);
	delete [] str_port;
	return ret_string;
}

vector<string>* Crafter::ParseIP(const string& str_argv) {
	/* Container of IP addresses */
	vector<string>* IPAddr = new vector<string>;

	/* context to hold state of ip range */
	ipv4_parse_ctx ctx;
	unsigned int addr = 0;
	int ret = 0;

	size_t argv_size = str_argv.size() + 1;
	char* argv = new char[argv_size];
	strncpy(argv,str_argv.c_str(),argv_size);
	/* Perform initial parsing of ip range */

	ret = ipv4_parse_ctx_init(&ctx, argv);
	if(ret < 0)
		throw std::runtime_error("ParseIP() : IP address parsing failed. Check the IP address supplied");

	/* Push out each ip in range */

	while(1) {
		/* get next ip in range */
		ret = ipv4_parse_next (&ctx, &addr);
		if(ret < 0)
			break;

		char ip_address[16];

		/* Print this out on a char array */
		sprintf(ip_address, "%d.%d.%d.%d", (addr >> 0) & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);

		/* Push in the container */
		IPAddr->push_back(string(ip_address));
	}

	delete [] argv;
	return IPAddr;
}

vector<string> Crafter::GetIPs(const string& str_argv) {
	/* Container of IP addresses */
	vector<string> IPAddr;

	/* context to hold state of ip range */
	ipv4_parse_ctx ctx;
	unsigned int addr = 0;
	int ret = 0;

	size_t argv_size = str_argv.size() + 1;
	char* argv = new char[argv_size];
	strncpy(argv,str_argv.c_str(),argv_size);
	/* Perform initial parsing of ip range */

	ret = ipv4_parse_ctx_init(&ctx, argv);
	if(ret < 0)
		throw std::runtime_error("ParseIP() : IP address parsing failed. Check the IP address supplied");

	/* Push out each ip in range */

	while(1) {
		/* get next ip in range */
		ret = ipv4_parse_next (&ctx, &addr);
		if(ret < 0)
			break;

		char ip_address[16];

		/* Print this out on a char array */
		sprintf(ip_address, "%d.%d.%d.%d", (addr >> 0) & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);

		/* Push in the container */
		IPAddr.push_back(string(ip_address));
	}

	delete [] argv;
	return IPAddr;
}

/* Convert a container of ip address strings into raw data in network byte order */
vector<byte> Crafter::IPtoRawData(const vector<string>& ips) {
	/* Get the size of the byte data */
	size_t data_size = ips.size() * sizeof(word);

	/* Create a container */
	vector<byte> raw_data(data_size,0);

	vector<string>::const_iterator it_str;

	size_t raw_counter = 0;

	for(it_str = ips.begin() ; it_str != ips.end() ; ++it_str) {
		struct in_addr num_ip = { inet_addr((*it_str).c_str()) };
		for(size_t i = 0; i < sizeof(word) ; i++) {
			raw_data[raw_counter] = ((byte*)&num_ip.s_addr)[i];
			raw_counter++;
		}
	}

	return raw_data;
}

/* Convert raw data in network byte order into a container of ip address strings */
vector<string> Crafter::RawDatatoIP(const vector<byte>& raw_data) {
	/* Container size */
	size_t raw_size = raw_data.size();
	size_t str_size = raw_size/4;

	size_t raw_counter = 0;

	vector<string> ips(str_size,"");

	for(size_t j = 0 ; j < str_size ; j++) {
	    struct in_addr ip_address;
		memcpy(&ip_address.s_addr ,&raw_data[raw_counter], sizeof(ip_address.s_addr));
		raw_counter += sizeof(ip_address.s_addr);
		/* Push the IP address in string format */
		ips[j] = string(inet_ntoa(ip_address));
	}

	return ips;
}

ARP* Crafter::GetARP(const Packet& packet) {
	return packet.GetLayer<ARP>();
}

Ethernet* Crafter::GetEthernet(const Packet& packet) {
	return packet.GetLayer<Ethernet>();
}

ICMP* Crafter::GetICMP(const Packet& packet){
	return packet.GetLayer<ICMP>();
}

IP* Crafter::GetIP(const Packet& packet){
	return packet.GetLayer<IP>();
}

IPv6* Crafter::GetIPv6(const Packet& packet){
	return packet.GetLayer<IPv6>();
}

IPLayer* Crafter::GetIPLayer(const Packet& packet) {
	return packet.GetLayer<IPLayer>();
}

TCP* Crafter::GetTCP(const Packet& packet){
	return packet.GetLayer<TCP>();
}

UDP* Crafter::GetUDP(const Packet& packet){
	return packet.GetLayer<UDP>();
}

RawLayer* Crafter::GetRawLayer(const Packet& packet){
	return packet.GetLayer<RawLayer>();
}

const Packet Crafter::operator/(const Layer& left, const Layer& right) {
	/* Create the packet */
	Packet ret_packet;

	ret_packet.PushLayer(left);
	ret_packet.PushLayer(right);

	return ret_packet;
}

const Packet Crafter::operator/(const Layer& left, const Packet& right) {
	/* Create the packet */
	Packet ret_packet;

	ret_packet.PushLayer(left);

	LayerStack::const_iterator it = right.begin();
	for(; it != right.end() ; it++)
		ret_packet.PushLayer(*(*it));

	return ret_packet;
}

void Crafter::CraftLayer(Layer* layer) {
	layer->Craft();
}
