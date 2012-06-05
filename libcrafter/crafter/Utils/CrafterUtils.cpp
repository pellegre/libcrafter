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

#include <pthread.h>
#include <cstdio>

#include <cstring> /* for strncpy */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>

#include "../Crafter.h"
#include "CrafterUtils.h"

#include "IPv4Parse.h"

using namespace Crafter;
using namespace std;

string Crafter::GetMyMAC(const string& iface) {
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, iface.c_str());

	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {

		const struct ether_addr *ptr = (const struct ether_addr *) (s.ifr_addr.sa_data);
		char buf[19];
		sprintf (buf, "%02x:%02x:%02x:%02x:%02x:%02x",
			  ptr->ether_addr_octet[0], ptr->ether_addr_octet[1],
			  ptr->ether_addr_octet[2], ptr->ether_addr_octet[3],
			  ptr->ether_addr_octet[4], ptr->ether_addr_octet[5]);
		buf[18] = 0;
		close(fd);
		return string(buf);

	} else {

		close(fd);
		return "";

	}
}

string Crafter::GetMyIP(const string& iface) {
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);

	if((ioctl(fd, SIOCGIFADDR, &ifr)) == -1) {
		Crafter::PrintMessage(Crafter::PrintCodes::PrintPerror,
					 "BindLinkSocketToInterface()",
					 "Getting Interface index");
		close(fd);
		return "";
	}

	close(fd);

	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
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
	if(ret < 0) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "ParseIP()",
		             "IP address parsing failed. Check the IP address supplied");
		exit(1);
	}

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



/* ------------------------ SendRcv Function -------------------------- */

struct PairMatch {
	/* Information about the Packets corresponding to the thread */
	int start;
	int num_threads;
	int total;
	/* Container */
	vector<Packet*>* PacketContainer;
	vector<Packet*>* Results;
	/* Arguments for sending */
	string iface;
	int timeout;
	int retry;
};

static void* SendRecvThread(void* thread_arg) {

	/* Cast the argument */
	PairMatch* pair = static_cast<PairMatch *>(thread_arg);

	/* Asign the values */
	int start = pair->start;
	int num_threads = pair->num_threads;
	int total = pair->total;

	vector<Packet*>* PacketContainer = pair->PacketContainer;
	vector<Packet*>* Results = pair->Results;

	for (int i = start ; i < total ; i += num_threads) {
		(*Results)[i] = (*PacketContainer)[i]->SendRecv(pair->iface,pair->timeout,pair->retry);
	}

	delete pair;

	/* Call pthread exit with a pointer to the new object */
	pthread_exit(NULL);
}

vector<Packet* >* Crafter::SendRecv(vector<Packet* >* PacketContainer, const string& iface, int num_threads, int timeout, int retry) {
	/* Total number of packets */
	int total = PacketContainer->size();

	/* Create the result container */
	vector<Packet*>* Results = new vector<Packet*>(total);

	if (total < num_threads) num_threads = total;

	/* Thread array */
	pthread_t* threads = new pthread_t[num_threads];

	/* Do the work on each packet */
	for(int i = 0 ; i < num_threads ; i++) {
		/* Create a pair structure */
		PairMatch* pair = new PairMatch;

		/* Asign values */
		pair->PacketContainer = PacketContainer;
		pair->Results = Results;

		/* Start value on the container */
		pair->start = i;

		/* Put the numbers of threads*/
		pair->num_threads = num_threads;

		/* Put the size of the container */
		pair->total = total;

		/* Set the arguments for the SendRecv function */
		pair->iface = iface;
		pair->timeout = timeout;
		pair->retry = retry;

		void* thread_arg = static_cast<void *>(pair);

		int rc = pthread_create(&threads[i], NULL, SendRecvThread, thread_arg);

		if (rc) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "BlockARP()",
			             "Creating thread. Returning code = " + StrPort(rc));
			exit(1);
		}

	}

	/* Join thread */
	for(int i = 0 ; i < num_threads ; i++) {
		void* ret;

		/* Join thread */
		int rc = pthread_join(threads[i], &ret);

		if (rc) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "BlockARP()",
			             "Joining thread. Returning code = " + StrPort(rc));
			exit(1);
		}

	}

	delete [] threads;

	return Results;
}

static void* SendThread(void* thread_arg) {

	/* Cast the argument */
	PairMatch* pair = static_cast<PairMatch *>(thread_arg);

	/* Asign the values */
	int start = pair->start;
	int num_threads = pair->num_threads;
	int total = pair->total;

	vector<Packet*>* PacketContainer = pair->PacketContainer;

	for (int i = start ; i < total ; i += num_threads)
		(*PacketContainer)[i]->Send(pair->iface);

	delete pair;

	/* Call pthread exit with a pointer to the new object */
	pthread_exit(NULL);
}

void Crafter::Send(vector<Packet* >* PacketContainer, const string& iface, int num_threads) {
	/* Total number of packets */
	int total = PacketContainer->size();

	if (total < num_threads) num_threads = total;

	/* Thread array */
	pthread_t* threads = new pthread_t[num_threads];

	/* Do the work on each packet */
	for(int i = 0 ; i < num_threads ; i++) {
		/* Create a pair structure */
		PairMatch* pair = new PairMatch;

		/* Asign values */
		pair->PacketContainer = PacketContainer;

		/* Start value on the container */
		pair->start = i;

		/* Put the numbers of threads*/
		pair->num_threads = num_threads;

		/* Put the size of the container */
		pair->total = total;

		/* Set the arguments for the SendRecv function */
		pair->iface = iface;

		void* thread_arg = static_cast<void *>(pair);

		int rc = pthread_create(&threads[i], NULL, SendThread, thread_arg);

		if (rc) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "Crafter::Send()",
			             "Creating thread. Returning code = " + StrPort(rc));
			exit(1);
		}

	}

	/* Join thread */
	for(int i = 0 ; i < num_threads ; i++) {
		void* ret;

		/* Join thread */
		int rc = pthread_join(threads[i], &ret);

		if (rc) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "BlockARP()",
			             "Joining thread. Returning code = " + StrPort(rc));
			exit(1);
		}

	}

	delete [] threads;

}

ARP* Crafter::GetARP(const Packet& packet) {
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = packet.begin() ; it_layer != packet.end() ; ++it_layer)
		if ((*it_layer)->GetName() == "ARP")
			return dynamic_cast<ARP*>( (*it_layer) );

	/* No requested layer, returns zero */
	return 0;
}

Ethernet* Crafter::GetEthernet(const Packet& packet) {
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = packet.begin() ; it_layer != packet.end() ; ++it_layer)
		if ((*it_layer)->GetName() == "Ethernet")
			return dynamic_cast<Ethernet*>( (*it_layer) );

	/* No requested layer, returns zero */
	return 0;
}

ICMP* Crafter::GetICMP(const Packet& packet){
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = packet.begin() ; it_layer != packet.end() ; ++it_layer)
		if ((*it_layer)->GetName() == "ICMP")
			return dynamic_cast<ICMP*>( (*it_layer) );

	/* No requested layer, returns zero */
	return 0;
}

IP* Crafter::GetIP(const Packet& packet){
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = packet.begin() ; it_layer != packet.end() ; ++it_layer)
		if ((*it_layer)->GetName() == "IP")
			return dynamic_cast<IP*>( (*it_layer) );

	/* No requested layer, returns zero */
	return 0;
}

TCP* Crafter::GetTCP(const Packet& packet){
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = packet.begin() ; it_layer != packet.end() ; ++it_layer)
		if ((*it_layer)->GetName() == "TCP")
			return dynamic_cast<TCP*>( (*it_layer) );

	/* No requested layer, returns zero */
	return 0;
}

UDP* Crafter::GetUDP(const Packet& packet){
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = packet.begin() ; it_layer != packet.end() ; ++it_layer)
		if ((*it_layer)->GetName() == "UDP")
			return dynamic_cast<UDP*>( (*it_layer) );

	/* No requested layer, returns zero */
	return 0;
}

RawLayer* Crafter::GetRawLayer(const Packet& packet){
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = packet.begin() ; it_layer != packet.end() ; ++it_layer)
		if ((*it_layer)->GetName() == "RawLayer")
			return dynamic_cast<RawLayer*>( (*it_layer) );

	/* No requested layer, returns zero */
	return 0;
}

const Packet Crafter::operator/(const Layer& left, const Layer& right) {
	/* Create the packet */
	Packet ret_packet;

	ret_packet.PushLayer(left);
	ret_packet.PushLayer(right);

	return ret_packet;
}

void Crafter::CraftLayer(Layer* layer) {
	layer->Craft();
}

void Crafter::InitCrafter() {

	IP ip_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&ip_dummy);

	UDP udp_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&udp_dummy);

	TCP tcp_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&tcp_dummy);

	ICMP icmp_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&icmp_dummy);

    ICMPExtension icmp_extension_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&icmp_extension_dummy);

    ICMPExtensionMPLS icmp_extension_mpls_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&icmp_extension_mpls_dummy);

    ICMPExtensionObject icmp_extension_object_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&icmp_extension_object_dummy);

	Ethernet ether_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&ether_dummy);

	ARP arp_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&arp_dummy);

	RawLayer raw_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&raw_dummy);

	DNS dns_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&dns_dummy);

	DHCP dhcp_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&dhcp_dummy);

	/* Init seed of RNG */
	srand(time(NULL));

	/* Put verbose mode as default */
	ShowWarnings = 1;

	/* Initialize Mutex variables */
	Packet::InitMutex();
	Sniffer::InitMutex();

}

void Crafter::CleanCrafter() {
	/* Destroy Mutex Varibles */
	Packet::DestroyMutex();
	Sniffer::DestroyMutex();
}
