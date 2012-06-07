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
#include <ifaddrs.h>
#include <net/if.h>

#include "../Crafter.h"
#include "CrafterUtils.h"

#include "IPv4Parse.h"
#include "IPResolver.h"

using namespace Crafter;
using namespace std;

string Crafter::GetMyMAC(const string& iface) {
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
}

string Crafter::GetMyIP(const string& iface) {
    struct ifaddrs* ifAddrStruct = 0;
    struct ifaddrs* ifa = 0;
    void* tmpAddrPtr = 0;
    /* Return value */
    string ret = "";

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != 0; ifa = ifa->ifa_next) {

    	/* Check if is a IPv6 */
        if (ifa->ifa_addr->sa_family==AF_INET) {
        	/* Check the interface */
        	if(string(ifa->ifa_name).find(iface) != string::npos) {
            	/* Is a valid IP6 Address */
                tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                char addressBuffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                ret = string(addressBuffer);
        	}
        }

    }

    if (ifAddrStruct!=0) freeifaddrs(ifAddrStruct);

    return ret;
}

string Crafter::GetMyIPv6(const string& iface) {
    struct ifaddrs* ifAddrStruct = 0;
    struct ifaddrs* ifa = 0;
    void* tmpAddrPtr = 0;
    /* Return value */
    string ret = "";

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != 0; ifa = ifa->ifa_next) {

    	/* Check if is a IPv6 */
        if (ifa->ifa_addr->sa_family==AF_INET6) {
        	/* Check the interface */
        	if(string(ifa->ifa_name).find(iface) != string::npos) {
            	/* Is a valid IP6 Address */
                tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
                char addressBuffer[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
                ret = string(addressBuffer);
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
	double timeout;
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

vector<Packet* >* Crafter::SendRecv(vector<Packet* >* PacketContainer, const string& iface, int num_threads, double timeout, int retry) {
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

void Crafter::DumpPcap(const std::string& filename, PacketContainer* pck_container)  {
	/* Check empty container, just in case */
	if(pck_container->size() == 0) return;

	/* Check the kind of packet that we are dealing with... We assume all the packets have the same format */
	Packet* pck = (*pck_container)[0];
	Layer* first = pck->GetLayer<Layer>(0);

	/* Get the link type */
	int link_type;
	if(first->GetName() == "Ethernet")
		link_type = DLT_EN10MB;           /* Packet begin with an Ethernet layer */
	else if (first->GetName() == "SLL")
		link_type = DLT_LINUX_SLL;        /* Linux cooked */
	else
		link_type = DLT_RAW;              /* Suppose all the packets begin with an IP layer */

    pcap_t *pd;
    pcap_dumper_t *pdumper;

    pd = pcap_open_dead(link_type, 65535 /* snaplen */);

    /* Create the output file. */
    pdumper = pcap_dump_open(pd, filename.c_str());

	/* Go through each packet */
	PacketContainer::iterator it_pck;

	for(it_pck = pck_container->begin() ; it_pck < pck_container->end() ; it_pck++) {
		/* pcap header */
		struct pcap_pkthdr header;
		/* TODO - libcrafter don't know anything about timestamps */
		header.ts.tv_sec = 0;
		header.ts.tv_usec = 0;
		header.len = (*it_pck)->GetSize();
		header.caplen = (*it_pck)->GetSize();
        pcap_dump(reinterpret_cast<u_char*>(pdumper), &header, (*it_pck)->GetRawPtr());
	}
    pcap_close(pd);
    pcap_dump_close(pdumper);
}

struct ReadData {
	int link_type;
	PacketContainer* pck_container;
};

/* Callback function to process a packet when captured */
static void process_packet (u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
	/* New packet on the heap */
	Packet* read_packet = new Packet;

	/* Argument for packet handling */
	ReadData* total_arg = reinterpret_cast<ReadData*>(user);

	/* Construct the packet */
	if(total_arg->link_type == DLT_RAW)
		read_packet->PacketFromIP(packet,header->len);
	else
		read_packet->PacketFromLinkLayer(packet, header->len,total_arg->link_type);

	/* Push this packet into the container */
	total_arg->pck_container->push_back(read_packet);
}

PacketContainer* Crafter::ReadPcap(const std::string& filename, const std::string& filter) {
	/* Handle for the opened pcap session */
	pcap_t *handle;
	/* Type of link layer of the interface */
	int link_type;
	/* Pcap error messages buffer */
	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = 0;
	/* Compiled BPF filter */
	struct bpf_program fp;

	handle = pcap_open_offline(filename.c_str(), errbuf);

	if (handle == NULL) {
	  /* There was an error */
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "Crafter::ReadPcap()",
	                 "opening the file: " + string(errbuf));
	  exit (1);
	}
	if (strlen (errbuf) > 0) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Crafter::ReadPcap()",
			         string(errbuf));
	  errbuf[0] = 0;    /* re-set error buffer */
	}

	/* Find out the datalink type of the connection */
	link_type = pcap_datalink(handle);

	if(filter.size() > 0) {
		/* Compile the filter, so we can capture only stuff we are interested in */
		if (pcap_compile (handle, &fp, filter.c_str(), 0, 0) == -1) {
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "Crafter::ReadPcap()",
			             "Compiling filter: " + string(pcap_geterr (handle)));
			cerr << "[!] Bad filter expression -> " << filter << endl;
			exit (1);
		}

		/* Set the filter for the device we have opened */
		if (pcap_setfilter (handle, &fp) == -1)	{
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "Crafter::ReadPcap()",
			             "Setting the filter: " + string(pcap_geterr (handle)) );
			exit (1);
		}
	}

	/* Create a new packet container */
	PacketContainer* pck_container = new PacketContainer;

	/* Prepare the data */
	ReadData rd;
	rd.link_type = link_type;
	rd.pck_container = pck_container;

	int r;
	u_char* arg = reinterpret_cast<u_char*>(&rd);

	if ((r = pcap_loop (handle, -1, process_packet, arg)) < 0) {
	  if (r == -1) {
		  /* Pcap error */
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "Sniffer::Sniffer()",
		                 "Error in pcap_loop " + string(pcap_geterr (handle)));
		  exit (1);
	  }
	  /* Otherwise return should be -2, meaning pcap_breakloop has been called */
	}

	return pck_container;
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

IPv6* Crafter::GetIPv6(const Packet& packet){
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = packet.begin() ; it_layer != packet.end() ; ++it_layer)
		if ((*it_layer)->GetName() == "IP")
			return dynamic_cast<IPv6*>( (*it_layer) );

	/* No requested layer, returns zero */
	return 0;
}

IPLayer* Crafter::GetIPLayer(const Packet& packet) {
	/* Search layer one by one */
	LayerStack::const_iterator it_layer;
	for (it_layer = packet.begin() ; it_layer != packet.end() ; ++it_layer)
		if ((*it_layer)->GetName() == "IP" || (*it_layer)->GetName() == "IPv6")
			return dynamic_cast<IPLayer*>( (*it_layer) );

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

	IPv6 ipv6_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&ipv6_dummy);

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

	SLL sll_dummy;
	/* Register the protocol, this is executed only once */
	Protocol::AccessFactory()->Register(&sll_dummy);

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
