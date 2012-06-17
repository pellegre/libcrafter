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

#include "ARPPing.h"

using namespace std;
using namespace Crafter;

void ARPAlive(Packet* sniff_packet, void* user) {
	/* Get the ARP header from the sniffed packet */
	ARP* arp_layer = GetARP(*sniff_packet);

	/* Cast the user pointer */
	map<string,string>* table = static_cast<map<string,string>* >(user);

	/* Update the table */
	(*table)[arp_layer->GetSenderIP()] = arp_layer->GetSenderMAC();

}

map<string,std::string> ARPPingSend(const string& ip_net, const string& iface, size_t send_count) {
	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	/* Get the MAC Address associated to the interface */
	string MyMAC = GetMyMAC(iface);

	/* --------- Common data to all headers --------- */

	Ethernet ether_header;

	ether_header.SetSourceMAC(MyMAC);
	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");   // <-- Set broadcast address

	ARP arp_header;

	arp_header.SetOperation(ARP::Request);                 // <-- Set Operation (ARP Request)
    arp_header.SetSenderIP(MyIP);                          // <-- Set our network data
    arp_header.SetSenderMAC(MyMAC);

    /* ---------------------------------------------- */

	/* Define the network to scan */
	vector<string> net = GetIPs(ip_net);                 // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator it_IP;                        // <-- Iterator

	/* Create a PacketContainer to hold all the ARP requests */
	PacketContainer request_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net.begin() ; it_IP != net.end() ; it_IP++) {

		arp_header.SetTargetIP(*it_IP);                    // <-- Set a destination IP address on ARP header

		/* Create a packet on the heap */
		Packet* packet = new Packet;

		/* Push the layers */
		packet->PushLayer(ether_header);
		packet->PushLayer(arp_header);

		/* Finally, push the packet into the container */
		request_packets.push_back(packet);
	}

	/* Create a sniffer for listen to ARP traffic of the network specified */
	Sniffer sniff("arp[7]=2",iface,ARPAlive);

	/* Create a table to hold IP and MAC addresses */
	map<string,string> table;

	void* sniffer_arg = static_cast<void*>(&table);

	/* Spawn the sniffer, the function returns immediately */
	sniff.Spawn(-1, sniffer_arg);

	/*
	 * At this point, we have all the packets into the
	 * request_packets container. Now we can Send 'Em All <send_count> times.
	 */
	for(size_t i = 0 ; i < send_count ; i++) {
		Send(request_packets.begin(), request_packets.end(), iface,16);
		sleep(1);
	}

	/* ... and close the sniffer */
	sniff.Cancel();

	/* Delete the container with the ARP requests */
	ClearContainer(request_packets);

	/* Return the table */
	return table;
}

map<string,std::string> ARPPingSendRcv(const string& ip_net, const string& iface, size_t send_count) {
	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	/* Get the MAC Address associated to the interface */
	string MyMAC = GetMyMAC(iface);

	/* --------- Common data to all headers --------- */

	Ethernet ether_header;

	ether_header.SetSourceMAC(MyMAC);
	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");   // <-- Set broadcast address

	ARP arp_header;

	arp_header.SetOperation(ARP::Request);                 // <-- Set Operation (ARP Request)
    arp_header.SetSenderIP(MyIP);                          // <-- Set our network data
    arp_header.SetSenderMAC(MyMAC);

    /* ---------------------------------------------- */

	/* Define the network to scan */
	vector<string> net = GetIPs(ip_net);                 // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator it_IP;                        // <-- Iterator

	/* Create a PacketContainer to hold all the ARP requests */
	PacketContainer request_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net.begin() ; it_IP != net.end() ; it_IP++) {

		arp_header.SetTargetIP(*it_IP);                    // <-- Set a destination IP address on ARP header

		/* Create a packet on the heap */
		Packet* packet = new Packet;

		/* Push the layers */
		packet->PushLayer(ether_header);
		packet->PushLayer(arp_header);

		/* Finally, push the packet into the container */
		request_packets.push_back(packet);
	}

	/* Create a table to hold IP and MAC addresses */
	map<string,string> table;

	/*
	 * At this point, we have all the packets into the
	 * request_packets container. Now we can Send 'Em All <send_count> times.
	 */
	PacketContainer replies_packets(request_packets.size());

	SendRecv(request_packets.begin(), request_packets.end(), replies_packets.begin(), iface, 0.1, send_count, 16);

	PacketContainer::iterator it_pck;
	for(it_pck = replies_packets.begin() ; it_pck < replies_packets.end() ; it_pck++) {
		/* Check if the pointer is not NULL */
		Packet* reply_packet = (*it_pck);
		if(reply_packet) {
			/* Get the ARP layer of the replied packet */
			ARP* arp_layer = GetARP(*reply_packet);
			/* Update the table */
			(table)[arp_layer->GetSenderIP()] = arp_layer->GetSenderMAC();
		}
	}

	/* Delete the container with the ARP requests */
	ClearContainer(request_packets);

	/* Delete the container with the responses, if there is one (check the NULL pointer) */
	ClearContainer(replies_packets);

	return table;
}

