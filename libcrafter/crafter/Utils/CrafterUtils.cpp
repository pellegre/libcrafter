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

#include "../Crafter.h"
#include "CrafterUtils.h"

#include <pthread.h>

#include "IPv4Parse.h"

using namespace Crafter;
using namespace std;

string Crafter::GetMyMAC(const string& iface) {
	/* Name of the device */
	char* device;
	/* Buffer for error messages */
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Find device for sniffing if needed */
	if (iface == "") {
	  /* If user hasn't specified a device */
	  device = pcap_lookupdev (errbuf); /* let pcap find a compatible device */
	  cout << "[@] MESSAGE: GetMyMAC() -> Using interface: " << device << endl;
	  if (device == NULL) {
		  /* there was an error */
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "GetMyMAC()",
		                 "Opening device -> " + string(errbuf));
		  exit (1);
	  }
	} else
	  device = (char *)iface.c_str();

	/* Libnet context */
	libnet_t *l = libnet_init (LIBNET_LINK, device, errbuf);

	if (l == 0) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "GetMyMAC()",
	                 "Opening libnet context: " + string(errbuf));
	  exit (1);
	}

	/* Now, get the mac address */
	u_int8_t* mac = (u_int8_t *) libnet_get_hwaddr(l);

	/* In case of error */
	if (!mac) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "GetMyMAC()",
		             "Unable to find MAC address for device " + string(device) + ": " + string(libnet_geterror(l)));
		exit (1);
	}

	/* Number of bytes on a MAC address */
	size_t n_ether_bytes = 6;
	/* Each MAC byte */
	char str[3] = {0};
	/* String to save the MAC address */
	string ret;

	/* Loop over the MAC's bytes */
	for(size_t i = 0 ; i < n_ether_bytes ; i++) {
		short_word dst = mac[i];
		sprintf(str,"%.2x",dst);
		if (i < n_ether_bytes - 1)
			ret += string(str)+":";
		else
			ret += string(str);
	}

	/* Free everything */
	libnet_destroy (l);

    return ret;
}

string Crafter::GetMyIP(const string& iface) {
	/* Name of the device */
	char* device;
	/* Buffer for error messages */
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Find device for sniffing if needed */
	if (iface == "") {
	  /* If user hasn't specified a device */
	  device = pcap_lookupdev (errbuf); /* let pcap find a compatible device */
	  cout << "[@] MESSAGE: GetMyIP() -> Using interface: " << device << endl;
	  if (device == NULL) {
		  /* there was an error */
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "GetMyIP()",
		                 "Opening device -> " + string(errbuf));
		  exit (1);
	  }
	} else
	  device = (char *)iface.c_str();

	/* Libnet context */
	libnet_t *l = libnet_init (LIBNET_LINK, device, errbuf);

	if (l == 0) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "GetMyIP()",
	                 "Opening context: " + string(errbuf));
	  exit (1);
	}

	/* Now, get the mac address */
	u_int32_t ip = libnet_get_ipaddr4(l);

	/* In case of error */
	if (ip == (u_int32_t)-1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "GetMyIP()",
		             "Unable to find IP address for device " + string(device) + ": " + string(libnet_geterror(l)));
		exit (1);
	}

	struct in_addr local_address;
	local_address.s_addr = ip;
	std::string ret(inet_ntoa(local_address));

	/* Free everything */
	libnet_destroy (l);

    return ret;
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
