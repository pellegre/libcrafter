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

const std::string Crafter::GetMAC(const std::string& IPAddress, const string& iface) {

	/* Create the Ethernet layer */
	Ethernet ether_layer;

	/* Set broadcast destination address */
	ether_layer.SetDestinationMAC("ff:ff:ff:ff:ff:ff");

	/* Create the ARP layer */
	ARP arp_layer;

	/* We want an ARP request */
	arp_layer.SetOperation(ARP::Request);

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

void Crafter::CleanARPContext(ARPContext* arp_context) {
	/* Get the thread ID and cancel the spoofing */
	pthread_t tid = arp_context->tid;

	int rc = pthread_cancel(tid);

	if (rc) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "CleanARPContext()",
		             "Cancelating thread. Returning code = " + StrPort(rc));
		exit(1);
	}

	/* Delete each packet on the container */
	PacketContainer::iterator it_packet;

	for(it_packet = arp_context->arp_packets->begin() ; it_packet != arp_context->arp_packets->end() ; it_packet++)
		delete(*it_packet);

	void* thread_arg = static_cast<void *>(arp_context);

	/* Clear the container */
	arp_context->arp_packets->clear();

	cout << "[@] Terminating ARPSpoofing. Trying to fix the ARP tables. " << endl;

	if(arp_context->type == ARPContext::Request)
		ARPNormalRequest(thread_arg);
	if(arp_context->type == ARPContext::Reply)
		ARPNormalReply(thread_arg);

	delete arp_context->TargetIPs;
	delete arp_context->TargetMACs;
	delete arp_context->VictimIPs;
	delete arp_context->VictimMACs;

	/* Delete the container */
	delete arp_context->arp_packets;

	delete arp_context;

	cout << "[@] Done cleaning up the ARPSpoofer. " << endl;
}

void ARPContext::SanityCheck() {
	/* Test performed before sending anything */
	vector<string>::iterator it;

	/* Check if the local MAC address is on any list, and remove it */
	size_t count = 0;
	for(it = TargetMACs->begin() ; it != TargetMACs->end() ; it++) {
		if( (*it) == AttackerMAC ) {
			it = TargetMACs->erase(it);
			/* And erase it from IP list */
			TargetIPs->erase(TargetIPs->begin() + count);
		}
		count++;
	}

	count = 0;
	for(it = VictimMACs->begin() ; it != VictimMACs->end() ; it++) {
		if( (*it) == AttackerMAC ) {
			it = VictimMACs->erase(it);
			/* And erase it from IP list */
			VictimIPs->erase(VictimIPs->begin() + count);
		}
		count++;
	}

	/* Now remove any target address which is on Victim list */
	vector<string>::iterator it_victim;

	for(it = TargetMACs->begin() ; it != TargetMACs->end() ; it++) {
		size_t count_victim = 0;
		for(it_victim = VictimMACs->begin() ; it_victim != VictimMACs->end() ; it_victim++) {
			if ( (*it_victim) == (*it) ) {
				it_victim = VictimMACs->erase(it_victim);
				/* And erase it from IP list */
				VictimIPs->erase(VictimIPs->begin() + count_victim);
			}
		}
		count_victim++;
	}

	if(TargetMACs->size() == 0) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "ARPContext::SanityCheck()",
		             "No host on Target net respond to ARP request. I have to abort, sorry. ");
		exit(1);
	}

	if(VictimMACs->size() == 0) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "ARPContext::SanityCheck()",
		             "No host on Victim net respond to ARP request. I have to abort, sorry. ");
		exit(1);
	}

}

void Crafter::BlockARP(ARPContext* context) {
	/* Get the thread ID and cancel the spoofing */
	pthread_t tid = context->tid;

	/* Block thread */
	void* ret;
	int rc = pthread_join(tid,&ret);

	if (rc) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "BlockARP()",
		             "Joining thread. Returning code = " + StrPort(rc));
		exit(1);
	}
}


void Crafter::PrintARPContext(const ARPContext& context) {
	/* Get size of both container */
	size_t size_victim = context.VictimIPs->size();
	size_t size_target = context.TargetIPs->size();

	/* Print victim net information */
	cout << "[@] --- Victim network " << endl;

	for (size_t i = 0 ; i < size_victim ; i++)
		cout << " IP : " << (*context.VictimIPs)[i] << " ; MAC : " << (*context.VictimMACs)[i] << endl;

	/* Print target net information */
	cout << "[@] --- Target network " << endl;

	for (size_t i = 0 ; i < size_target ; i++)
		cout << " IP : " << (*context.TargetIPs)[i] << " ; MAC : " << (*context.TargetMACs)[i] << endl;

}
