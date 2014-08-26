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


#include "Sniffer.h"
#include "CrafterUtils.h"

using namespace std;
using namespace Crafter;

/* Handle for packets sniffed in pcap session */
static vector<Packet::PacketHandler> packet_handler;

/* Mutex variable for no-reentrant functions */
pthread_mutex_t Sniffer::mutex_compile;

/* Class global counter */
word Sniffer::counter = 0;

/* Callback function to process a packet when captured */
static void process_packet (u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
	Packet sniff_packet;

	/* Argument for packet handling */
	SnifferData* total_arg = reinterpret_cast<SnifferData*>(user);

	/* Set packet time stamp */
	sniff_packet.SetTimestamp(header->ts);

	/* Construct the packet */
	sniff_packet.PacketFromLinkLayer(packet, header->len,total_arg->link_type);

	/* Grab the data */
	word sniff_id = total_arg->ID;
	void* arg = total_arg->sniffer_arg;
	/* Execute function */
	packet_handler[sniff_id](&sniff_packet, arg);
}

/* Default packet handling function */
static void DefaultPckHand(Packet* sniff_packet, void* user) {
	sniff_packet->Print(cout);
	cout << "[+] ******* [+]" << endl;
}

/* Set filter */
void Crafter::Sniffer::SetFilter(const std::string& filter) {
	/* Set the filter specified by the user */
	this->filter = filter;

	/* And compile it */
	CompileFilter();
}

/* Set device interface */
void Crafter::Sniffer::SetInterface(const std::string& iface) {
	/* Close our devices */
	pcap_close (handle);

	/* Set device */
    device = (char *)iface.c_str();

    /* ------ Update all the fields */

	/* set errbuf to 0 length string to check for warnings */
	errbuf[0] = 0;

	/* open device for sniffing */
	handle = pcap_open_live (device,  /* device to sniff on */
						     BUFSIZ,  /* maximum number of bytes to capture per packet */
									  /* BUFSIZE is defined in pcap.h */
						     1,       /* promisc - 1 to set card in promiscuous mode, 0 to not */
						     0,       /* to_ms - amount of time to perform packet capture in milliseconds */
									  /* 0 = sniff until error */
						     errbuf); /* error message buffer if something goes wrong */
	if (handle == NULL)
	  /* there was an error */
		throw std::runtime_error("Sniffer::SetInterface() : Opening sniffer: " + string(errbuf));

	if (strlen (errbuf) > 0) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Sniffer::SetInterface()",
			         string(errbuf));

	  errbuf[0] = 0;    /* re-set error buffer */
	}

	/* Find out the datalink type of the connection */
	link_type = pcap_datalink(handle);

	/* Get the IP subnet mask of the device, so we set a filter on it */
	if (pcap_lookupnet (device, &netp, &maskp, errbuf) == -1) {
		maskp = PCAP_NETMASK_UNKNOWN;
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				"Sniffer::Sniffer() : Looking net parameters: " + string(errbuf));
	}

	/* And compile the filter */
	CompileFilter();
}

/* Set Packet Handler function */
void Crafter::Sniffer::SetPacketHandler(Packet::PacketHandler PacketHandlerFunction) {
	packet_handler[ID] = PacketHandlerFunction;
}

void Crafter::Sniffer::CompileFilter() {

	/* ----------- Begin Critical area ---------------- */

    pthread_mutex_lock (&mutex_compile);

	/* Compile the filter, so we can capture only stuff we are interested in */
	if (pcap_compile (handle, &fp, filter.c_str(), 0, maskp) == -1)
		throw std::runtime_error("Sniffer::CompileFilter() : Compiling filter: " + string(pcap_geterr (handle)));


	/* Set the filter for the device we have opened */
	if (pcap_setfilter (handle, &fp) == -1)
		throw std::runtime_error("Sniffer::CompileFilter() : Setting filter: " + string(pcap_geterr (handle)));


	/* We'll be nice and free the memory used for the compiled filter */
	pcap_freecode (&fp);

    pthread_mutex_unlock (&mutex_compile);

	/* ------------ End Critical area ----------------- */
}

Crafter::Sniffer::Sniffer(const std::string& filter, const std::string& iface, Packet::PacketHandler PacketHandlerFunction) {
	/* Set the spawned flag to zero */
	spawned = 0;

	/* Set the filter */
	this->filter = filter;

	/* Get pointer for capture data */
	sniffer_data = new SnifferData;

	/* Find device for sniffing if needed */
	if (iface == "") {
	  /* If user hasn't specified a device */
	  device = pcap_lookupdev (errbuf); /* let pcap find a compatible device */
	  if (device == NULL)
		  /* there was an error */
			throw std::runtime_error("Sniffer::Sniffer() : Error looking device for sniffing " + string(errbuf));

	} else
	  device = (char *)iface.c_str();

	/* Set errbuf to 0 length string to check for warnings */
	errbuf[0] = 0;

	/* Open device for sniffing */
	handle = pcap_open_live (device,  /* device to sniff on */
						     BUFSIZ,  /* maximum number of bytes to capture per packet */
									  /* BUFSIZE is defined in pcap.h */
						     1,       /* promisc - 1 to set card in promiscuous mode, 0 to not */
						     0,       /* to_ms - amount of time to perform packet capture in milliseconds */
									  /* 0 = sniff until error */
						     errbuf); /* error message buffer if something goes wrong */
	if (handle == NULL)
	  /* There was an error */
		throw std::runtime_error("Sniffer::Sniffer() : opening the sniffer: " + string(errbuf));

	if (strlen (errbuf) > 0) {
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				     "Sniffer::Sniffer()",
			         string(errbuf));
	  errbuf[0] = 0;    /* re-set error buffer */
	}

	/* Find out the datalink type of the connection */
	link_type = pcap_datalink(handle);

	/* Get the IP subnet mask of the device, so we set a filter on it */
	if (pcap_lookupnet (device, &netp, &maskp, errbuf) == -1) {
		maskp = PCAP_NETMASK_UNKNOWN;
		PrintMessage(Crafter::PrintCodes::PrintWarning,
				"Sniffer::Sniffer() : Looking net parameters: " + string(errbuf));
	}

	/* ----------- Begin Critical area ---------------- */

    pthread_mutex_lock (&mutex_compile);

	/* Compile the filter, so we can capture only stuff we are interested in */
	if (pcap_compile (handle, &fp, filter.c_str(), 0, maskp) == -1) {
		cerr << "[!] Bad filter expression -> " << filter << endl;
		throw std::runtime_error("Sniffer::Sniffer() : Compiling filter: " + string(pcap_geterr (handle)));
	}

	/* Set the filter for the device we have opened */
	if (pcap_setfilter (handle, &fp) == -1)
		throw std::runtime_error("Sniffer::Sniffer() : Setting the filter: " + string(pcap_geterr (handle)) );

	/* We'll be nice and free the memory used for the compiled filter */
	pcap_freecode (&fp);

	/* Set ID of the sniffer */
	ID = counter;

	/* Sum one to the counter */
	counter++;

	/* Set Packet Handler */
	if (PacketHandlerFunction)
		packet_handler.push_back(PacketHandlerFunction);
	else
		packet_handler.push_back(DefaultPckHand);

    pthread_mutex_unlock (&mutex_compile);

	/* ------------ End Critical area ----------------- */

}

/* Start capturing packets */
void Crafter::Sniffer::Capture(uint32_t count, void *user) {
	int r;

	sniffer_data->ID = ID;
	sniffer_data->sniffer_arg = user;
	sniffer_data->link_type = link_type;

	u_char* sniffer_data_arg = reinterpret_cast<u_char*>(sniffer_data);

	if ((r = pcap_loop (handle, count, process_packet, sniffer_data_arg)) < 0) {
	  if (r == -1)
		  /* Pcap error */
			throw std::runtime_error("Sniffer::Sniffer() : Error in pcap_loop " + string(pcap_geterr (handle)));

	  /* Otherwise return should be -2, meaning pcap_breakloop has been called */
	  return;
	}
}

void* SpawnThread(void* thread_arg) {
	/* Cast back the argument */
	SpawnData* spawn_data = static_cast<SpawnData*>(thread_arg);

	/* User argument */
	void* user = spawn_data->user;
	/* Packet count, for Capture argument */
	uint32_t count = spawn_data->count;
	/* Pointer to the sniffer */
	Sniffer* sniff_ptr = spawn_data->sniff_ptr;
	/* Free the spawn data */
	delete spawn_data;

	/* Just capture */
	sniff_ptr->Capture(count,user);

	/* Exit the function */
	pthread_exit(NULL);
}

void Crafter::Sniffer::Spawn(uint32_t count, void *user) {
	/* Mark the sniffer as spawned */
	spawned = 1;

	/* First, get the data for spawning a thread */
	SpawnData* spawn_data = new SpawnData;

	/* Packet count */
	spawn_data->count = count;
	/* Data from the user */
	spawn_data->user = user;
	/* Pointer to this sniffer */
	spawn_data->sniff_ptr = this;

	/* Cast the spawn data */
	void* thread_arg = static_cast<void*>(spawn_data);

	/* Now, spawn a thread */
	int rc = pthread_create(&thread_id, NULL, SpawnThread, thread_arg);

	if (rc)
		throw std::runtime_error("Sniffer::Spawn() : Creating thread. Returning code = " + StrPort(rc));

}

void Crafter::Sniffer::Join() {
	/* Get the thread ID and block the thread until the work is done */

	void* ret;
	int rc = pthread_join(thread_id,&ret);

	if (rc)
		throw std::runtime_error("Sniffer::Join() : Joining thread. Returning code = " + StrPort(rc));

}

void Crafter::Sniffer::Cancel() {

	if(spawned) {
		pcap_breakloop(handle);
		/* If the thread was spawned, call pthread_cancel for terminating the sniffing */
		int rc = pthread_cancel(thread_id);

		if (rc)
			throw std::runtime_error("Sniffer::Cancel() : Cancelating thread. Returning code = " + StrPort(rc));

	} else
		/* Just call to pcap_breakloop */
		pcap_breakloop(handle);

}

void Sniffer::InitMutex() {
    pthread_mutex_init(&Sniffer::mutex_compile, NULL);
}

void Sniffer::DestroyMutex() {
    pthread_mutex_destroy(&Sniffer::mutex_compile);
}

Crafter::Sniffer::~Sniffer() {
	delete sniffer_data;

	/* Close our devices */
	pcap_close (handle);
}
