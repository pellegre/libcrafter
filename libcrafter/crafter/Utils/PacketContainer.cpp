/*
 * PacketContainer.cpp
 *
 *  Created on: Jun 7, 2012
 *      Author: larry
 */

#include "PacketContainer.h"

using namespace std;
using namespace Crafter;

/* ------------------------ SendRcv Function -------------------------- */

struct PairMatch {
	/* Information about the Packets corresponding to the thread */
	int start;
	int num_threads;
	int total;
	/* Container */
	PacketContainer* PktContainer;
	PacketContainer* Results;
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

	PacketContainer* PktContainer = pair->PktContainer;
	PacketContainer* Results = pair->Results;

	for (int i = start ; i < total ; i += num_threads) {
		(*Results)[i] = (*PktContainer)[i]->SendRecv(pair->iface,pair->timeout,pair->retry);
	}

	delete pair;

	/* Call pthread exit with a pointer to the new object */
	pthread_exit(NULL);
}

PacketContainer* Crafter::PacketContainer::SendRecvMultiThread(const string& iface, double timeout, int retry, int num_threads) {
	/* Total number of packets */
	int total = size();

	/* Create the result container */
	PacketContainer* Results = new PacketContainer(total);

	if (total < num_threads) num_threads = total;

	/* Thread array */
	pthread_t* threads = new pthread_t[num_threads];

	/* Do the work on each packet */
	for(int i = 0 ; i < num_threads ; i++) {
		/* Create a pair structure */
		PairMatch* pair = new PairMatch;

		/* Assign values */
		pair->PktContainer = this;
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
			             "Creating thread. Returning code = " + toString(rc));
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
			             "Joining thread. Returning code = " + toString(rc));
			exit(1);
		}

	}

	delete [] threads;

	return Results;
}

PacketContainer* Crafter::PacketContainer::SendRecvLoop(const std::string& iface, double timeout, int retry) {
	/* Create the result container */
	PacketContainer* Results = new PacketContainer;
	iterator it = begin();
	for(; it != end() ; it++)
		Results->push_back((*it)->SendRecv(iface,timeout,retry));
	return Results;
}

static void* SendThread(void* thread_arg) {

	/* Cast the argument */
	PairMatch* pair = static_cast<PairMatch *>(thread_arg);

	/* Assign the values */
	int start = pair->start;
	int num_threads = pair->num_threads;
	int total = pair->total;

	PacketContainer* PktContainer = pair->PktContainer;

	for (int i = start ; i < total ; i += num_threads)
		(*PktContainer)[i]->Send(pair->iface);

	delete pair;

	/* Call pthread exit with a pointer to the new object */
	pthread_exit(NULL);
}

void Crafter::PacketContainer::SendMultiThread(const string& iface, int num_threads) {
	/* Total number of packets */
	int total = size();

	if (total < num_threads) num_threads = total;

	/* Thread array */
	pthread_t* threads = new pthread_t[num_threads];

	/* Do the work on each packet */
	for(int i = 0 ; i < num_threads ; i++) {
		/* Create a pair structure */
		PairMatch* pair = new PairMatch;

		/* Asign values */
		pair->PktContainer = this;

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
			             "Creating thread. Returning code = " + toString(rc));
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
			             "Joining thread. Returning code = " + toString(rc));
			exit(1);
		}

	}

	delete [] threads;

}

void Crafter::PacketContainer::SendLoop(const std::string& iface) {
	iterator it = begin();

	for(;it != end() ; it++)
		(*it)->Send(iface);

}

void Crafter::PacketContainer::DumpPcap(const std::string& filename)  {
	/* Check empty container, just in case */
	if(size() == 0) return;

	/* Check the kind of packet that we are dealing with... We assume all the packets have the same format */
	Packet* pck = (*this)[0];
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
	iterator it_pck;

	for(it_pck = begin() ; it_pck < end() ; it_pck++) {
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

void Crafter::PacketContainer::ReadPcap(const std::string& filename, const std::string& filter) {
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

	/* Prepare the data */
	ReadData rd;
	rd.link_type = link_type;
	rd.pck_container = this;

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

	pcap_close(handle);

}

/* Send the packets */
void Crafter::PacketContainer::Send(const std::string& iface, int num_threads) {
	if(num_threads)
		SendMultiThread(iface,num_threads);
	else
		SendLoop(iface);
}

/* Send and Receive the container  */
PacketContainer* Crafter::PacketContainer::SendRecv(const std::string& iface, double timeout, int retry, int num_threads) {
	if(num_threads)
		return SendRecvMultiThread(iface,timeout,retry,num_threads);
	else
		return SendRecvLoop(iface,timeout,retry);
}

void Crafter::PacketContainer::ClearPackets() {
	iterator it = begin();

	for(; it != end() ; it++)
		if((*it)) delete (*it);

	clear();
}
