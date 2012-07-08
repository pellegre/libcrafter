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

#include "PacketContainer.h"

using namespace std;
using namespace Crafter;

void Crafter::OpenPcapDumper(int link_type, const string& filename, pcap_t*& pd, pcap_dumper_t*& pdumper) {
	/* Open pcap file */
    pd = pcap_open_dead(link_type, 65535 /* snaplen */);
    /* Create the output file. */
    pdumper = pcap_dump_open(pd, filename.c_str());
}

void Crafter::ClosePcapDumper(pcap_t* pd, pcap_dumper_t* pdumper) {
    pcap_close(pd);
    pcap_dump_close(pdumper);
}

void Crafter::DumperPcap(pcap_dumper_t* pdumper, struct pcap_pkthdr* header, const byte* raw_data) {
    pcap_dump(reinterpret_cast<u_char*>(pdumper), header, raw_data);
}

void Crafter::OpenOffPcap(int* link_type, pcap_t*& handle, const string& filename, const string& filter) {
	/* PCAP error messages buffer */
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
	*link_type = pcap_datalink(handle);

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

		pcap_freecode(&fp);
	}

}

void Crafter::LoopPcap(pcap_t *handle, int cnt, pcap_handler callback, u_char *user) {
	int r;
	if ((r = pcap_loop (handle, cnt, callback, user)) < 0) {
	  if (r == -1) {
		  /* Pcap error */
			PrintMessage(Crafter::PrintCodes::PrintError,
					     "Crafter::ReadPcap()",
		                 "Error in pcap_loop " + string(pcap_geterr (handle)));
		  exit (1);
	  }
	  /* Otherwise return should be -2, meaning pcap_breakloop has been called */
	}
}

void Crafter::ClosePcap(pcap_t *handle) {
	pcap_close(handle);
}

struct ReadData {
	Packet::PacketHandler packet_handler;
	void* user_arg;
	int link_type;
};

/* Callback function to process a packet after read it */
static void process_packet (u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
	Packet sniff_packet;

	/* Argument for packet handling */
	ReadData* total_arg = reinterpret_cast<ReadData*>(user);

	/* Construct the packet */
	sniff_packet.PacketFromLinkLayer(packet,header->len,total_arg->link_type);

	/* Grab the data */
	Packet::PacketHandler PacketHandlerFunction = total_arg->packet_handler;
	void* arg = total_arg->user_arg;

	/* Execute function */
	PacketHandlerFunction(&sniff_packet, arg);
}

void Crafter::ReadPcap(const std::string& filename, Packet::PacketHandler PacketHandlerFunction, void* user, const std::string& filter) {
	/* Handle for the opened pcap session */
	pcap_t *handle;
	/* Type of link layer of the interface */
	int link_type;

	OpenOffPcap(&link_type,handle,filename,filter);

	/* Prepare the data */
	ReadData rd;
	rd.link_type = link_type;
	rd.packet_handler = PacketHandlerFunction;
	rd.user_arg = user;

	u_char* arg = reinterpret_cast<u_char*>(&rd);

	LoopPcap(handle,-1,process_packet,arg);

	ClosePcap(handle);
}

/* ---------------- Send an Receive functions (wrappers for backward compatibility) -------------- */

/* DEPRECATED functions */

/* Dump packet container on a pcap file */
void Crafter::DumpPcap(const std::string& filename, PacketContainer* pck_container) {
	PrintMessage(Crafter::PrintCodes::PrintWarning,
			     "Crafter::DumpPcap()",
		         "Deprecated function, please consider to use newer functions with iterators as arguments.");
	DumpPcap(pck_container->begin(), pck_container->end(), filename);
}

/* Read a pcap file */
PacketContainer* Crafter::ReadPcap(const std::string& filename, const std::string& filter) {
	PrintMessage(Crafter::PrintCodes::PrintWarning,
			     "Crafter::ReadPcap()",
		         "Deprecated function, please consider to use newer functions with iterators as arguments.");
	PacketContainer* pck_ptr = new PacketContainer;
	ReadPcap(pck_ptr,filename,filter);
	return pck_ptr;
}

/* Send and Receive a container of packet */
PacketContainer* Crafter::SendRecv(PacketContainer* pck_container, const std::string& iface,
		                  int num_threads, double timeout, int retry) {
	PrintMessage(Crafter::PrintCodes::PrintWarning,
			     "Crafter::SendRecv()",
		         "Deprecated function, please consider to use newer functions with iterators as arguments.");
	PacketContainer* pck_ptr = new PacketContainer(pck_container->size());
	SendRecv(pck_container->begin(), pck_container->end(), pck_ptr->begin(), iface, timeout, retry, num_threads);
	return pck_ptr;
}

/* Send a container of packet - Multithreading */
void Crafter::Send(PacketContainer* pck_container, const std::string& iface, int num_threads) {
	PrintMessage(Crafter::PrintCodes::PrintWarning,
			     "Crafter::Send()",
		         "Deprecated function, please consider to use newer functions with iterators as arguments.");
	Send(pck_container->begin(), pck_container->end(), iface, num_threads);
}
