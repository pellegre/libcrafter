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


#include "ARPSpoofing.h"
#include <signal.h>

using namespace std;
using namespace Crafter;

void Crafter::CleanARPContext(ARPContext* arp_context) {
	/* Get the thread ID and cancel the spoofing */
	arp_context->keep_going = false;

	int rc = pthread_join(arp_context->tid, NULL);

	if (rc)
		throw std::runtime_error("CleanARPContext() : Cancelating thread. Returning code = " + StrPort(rc));

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
			if (it == TargetMACs->end())
				/* We deleted the last element, stop here. */
				break;
		}
		count++;
	}

	count = 0;
	for(it = VictimMACs->begin() ; it != VictimMACs->end() ; it++) {
		if( (*it) == AttackerMAC ) {
			it = VictimMACs->erase(it);
			/* And erase it from IP list */
			VictimIPs->erase(VictimIPs->begin() + count);
			if (it == VictimMACs->end())
				/* We deleted the last element, stop here. */
				break;
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
				if (it_victim == VictimMACs->end())
					/* We deleted the last element, stop here. */
					break;
			}
		}
		count_victim++;
	}

	if(TargetMACs->size() == 0)
		throw std::runtime_error("ARPContext::SanityCheck() : No host on Target net respond to ARP request. I have to abort, sorry. ");

	if(VictimMACs->size() == 0)
		throw std::runtime_error("ARPContext::SanityCheck() : No host on Victim net respond to ARP request. I have to abort, sorry. ");

}

void Crafter::BlockARP(ARPContext* context) {
	/* Get the thread ID and cancel the spoofing */
	pthread_t tid = context->tid;

	/* Block thread */
	void* ret;
	int rc = pthread_join(tid,&ret);

	if (rc)
		throw std::runtime_error("BlockARP() : Joining thread. Returning code = " + StrPort(rc));

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
