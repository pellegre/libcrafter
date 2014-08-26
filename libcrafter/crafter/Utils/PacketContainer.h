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

#ifndef PACKETCONTAINER_H_
#define PACKETCONTAINER_H_

#include <iostream>
#include <sstream>
#include <iterator>
#include <vector>
#include <string>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>

#include "../Crafter.h"

namespace Crafter {

	template<typename T>
	static T fromString(const std::string& str) {
		std::istringstream s(str);
		T t;
		s >> t;
		return t;
	}

	template<typename T>
	static std::string toString(const T& t) {
		std::ostringstream s;
		s << t;
		return s.str();
	}

	template<typename FowardIter, typename OutputIter>
	struct ThreadData {
		/* Container interators */
		FowardIter beginIterator;
		OutputIter beginOutput;
		/* Arguments for sending */
		std::string iface;
		int num_threads;
		size_t start_count;
		size_t total;
		double timeout;
		int retry;
		int sd;
	};

	/* +++++++++++++++++++ Auxiliary Functions declaration  +++++++++++++++++++ */

	void OpenPcapDumper(int link_type, const std::string& filename, pcap_t*& pd, pcap_dumper_t*& pdumper);

	void ClosePcapDumper(pcap_t* pd, pcap_dumper_t* pdumper);

	void DumperPcap(pcap_dumper_t* pdumper, struct pcap_pkthdr* header, const byte* raw_data);

	void OpenOffPcap(int* link_type, pcap_t*& handle, const std::string& filename, const std::string& filter);

	void LoopPcap(pcap_t *p, int cnt, pcap_handler callback, u_char *user);

	void ClosePcap(pcap_t *p);

	/* +++++++++++++++++++ Apply Container +++++++++++++++++++++ */

	template<class Seq>
	void ClearContainer(Seq& seq) {
		typename Seq::iterator it = seq.begin();
		while (it != seq.end()) {
			delete (*it);
			it++;
		}
	}

	/* PreCraft a range of packets defined with forward iterators */
	template<typename FowardIter>
	void PreCraft(FowardIter begin, FowardIter end) {
		while(begin != end) {
			(*begin)->PreCraft();
			begin++;
		}
	}

	/* +++++++++++++++++++ Send the packets +++++++++++++++++++++ */

	/* This function is executed by a thread */
	template<typename FowardIter>
	void* SendThreadIterator(void* thread_arg) {

		/* Cast the argument */
		ThreadData<FowardIter,FowardIter>* pair = static_cast<ThreadData<FowardIter,FowardIter> *>(thread_arg);

		/* Assign the values */
		int num_threads = pair->num_threads;
		FowardIter begin = pair->beginIterator;
		size_t total = pair->total;
		/* Count packets */
		size_t count = pair->start_count;
		while(count < total) {
			(*begin)->Send(pair->iface);
			count += num_threads;
			if(count > total) break;
			advance(begin,num_threads);
		}

		delete pair;

		/* Call pthread exit */
		pthread_exit(NULL);
	}

	/* A multithreaded Send function */
	template<typename FowardIter>
	void SendMultiThread(FowardIter begin, FowardIter end, const std::string& iface, int num_threads) {
		/* Total number of packets */
		int total = distance(begin,end);
		if (total < num_threads) num_threads = total;

		/* Thread array */
		pthread_t* threads = new pthread_t[num_threads];

		/* Do the work on each packet */
		for(int i = 0 ; i < num_threads ; i++) {
			/* Create a pair structure */
			ThreadData<FowardIter,FowardIter>* pair = new ThreadData<FowardIter,FowardIter>;

			/* Start value on the container */
			pair->beginIterator = begin;
			advance(pair->beginIterator,i);
			/* Start value for the counter */
			pair->start_count = i;
			/* Put the number of threads */
			pair->num_threads = num_threads;
			/* Put the size of the container */
			pair->total = total;
			/* Set the arguments for the SendRecv function */
			pair->iface = iface;

			void* thread_arg = static_cast<void *>(pair);

			int rc = pthread_create(&threads[i], NULL, SendThreadIterator<FowardIter>, thread_arg);

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

	/* Send a range of packets defined with forward iterators */
	template<typename FowardIter>
	void Send(FowardIter begin, FowardIter end, const std::string& iface = "", int num_threads = 0) {
		if(num_threads == 0) {
			while(begin != end) {
				(*begin)->Send(iface);
				begin++;
			}
		}
		else
			SendMultiThread(begin,end,iface,num_threads);
	}

	/* This function is executed by a thread */
	template<typename FowardIter>
	void* SocketSendThreadIterator(void* thread_arg) {

		/* Cast the argument */
		ThreadData<FowardIter,FowardIter>* pair = static_cast<ThreadData<FowardIter,FowardIter> *>(thread_arg);

		/* Assign the values */
		int num_threads = pair->num_threads;
		FowardIter begin = pair->beginIterator;
		size_t total = pair->total;
		/* Count packets */
		size_t count = pair->start_count;
		while(count < total) {
			(*begin)->SocketSend(pair->sd);
			count += num_threads;
			if(count > total) break;
			advance(begin,num_threads);
		}

		delete pair;

		/* Call pthread exit */
		pthread_exit(NULL);
	}

	/* A multithreaded Send function */
	template<typename FowardIter>
	void SocketSendMultiThread(int sd, FowardIter begin, FowardIter end, int num_threads) {
		/* Total number of packets */
		int total = distance(begin,end);
		if (total < num_threads) num_threads = total;

		/* Thread array */
		pthread_t* threads = new pthread_t[num_threads];

		/* Do the work on each packet */
		for(int i = 0 ; i < num_threads ; i++) {
			/* Create a pair structure */
			ThreadData<FowardIter,FowardIter>* pair = new ThreadData<FowardIter,FowardIter>;

			/* Start value on the container */
			pair->beginIterator = begin;
			advance(pair->beginIterator,i);
			/* Start value for the counter */
			pair->start_count = i;
			/* Put the number of threads */
			pair->num_threads = num_threads;
			/* Put the size of the container */
			pair->total = total;
			/* Save the socket descriptor */
			pair->sd = sd;

			void* thread_arg = static_cast<void *>(pair);

			int rc = pthread_create(&threads[i], NULL, SocketSendThreadIterator<FowardIter>, thread_arg);

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

	/* Send a range of packets defined with forward iterators */
	template<typename FowardIter>
	void SocketSend(int sd, FowardIter begin, FowardIter end, int num_threads = 0) {
		if(num_threads == 0) {
			while(begin != end) {
				(*begin)->SocketSend(sd);
				begin++;
			}
		}
		else
			SocketSendMultiThread(sd,begin,end,num_threads);
	}
	/* +++++++++++++++++++ Send and Receive the packets +++++++++++++++++++++ */

	/* This function is executed by a thread */
	template<typename FowardIter, typename OutputIter>
	void* SendRecvThreadIterator(void* thread_arg) {

		/* Cast the argument */
		ThreadData<FowardIter,OutputIter>* pair = static_cast<ThreadData<FowardIter,OutputIter> *>(thread_arg);

		/* Assign the values */
		int num_threads = pair->num_threads;
		FowardIter begin = pair->beginIterator;
		OutputIter out_begin = pair->beginOutput;
		size_t total = pair->total;
		int retry = pair->retry;
		double timeout = pair->timeout;
		/* Count packets */
		size_t count = pair->start_count;
		while(count < total) {
			(*begin)->SendRecvPtr(pair->iface,timeout,retry," ",(*out_begin));
			count += num_threads;
			if(count > total) break;
			advance(begin,num_threads);
			advance(out_begin,num_threads);
		}

		delete pair;

		/* Call pthread exit */
		pthread_exit(NULL);
	}

	/* A multithreaded Send function */
	template<typename FowardIter, typename OutputIter>
	void SendRecvMultiThread(FowardIter begin, FowardIter end, OutputIter out_begin,
			                 const std::string& iface, double timeout, int retry, int num_threads) {
		/* Total number of packets */
		int total = distance(begin,end);
		if (total < num_threads) num_threads = total;

		/* Thread array */
		pthread_t* threads = new pthread_t[num_threads];

		/* Do the work on each packet */
		for(int i = 0 ; i < num_threads ; i++) {
			/* Create a pair structure */
			ThreadData<FowardIter,OutputIter>* pair = new ThreadData<FowardIter,OutputIter>;

			/* Start value on the container */
			pair->beginIterator = begin;
			advance(pair->beginIterator,i);
			/* Start value of output iterator */
			pair->beginOutput = out_begin;
			advance(pair->beginOutput,i);
			/* Start value for the counter */
			pair->start_count = i;
			/* Put the number of threads */
			pair->num_threads = num_threads;
			/* Put the size of the container */
			pair->total = total;
			/* Set the arguments for the SendRecv function */
			pair->iface = iface;
			/* Number of times the packet is sent */
			pair->retry = retry;
			/* Timeout */
			pair->timeout = timeout;

			void* thread_arg = static_cast<void *>(pair);

			int rc = pthread_create(&threads[i], NULL, SendRecvThreadIterator<FowardIter,OutputIter>, thread_arg);

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

	/* Send a range of packets defined with forward iterators */
	template<typename FowardIter, typename OutputIter>
	void SendRecv(FowardIter begin, FowardIter end, OutputIter out_begin,
			      const std::string& iface = "", double timeout = 1, int retry = 3, int num_threads = 0) {

		if(num_threads == 0) {
				while(begin != end) {
					(*begin)->SendRecvPtr(iface,timeout,retry," ",(*out_begin));
					begin++;
					out_begin++;
				}
		} else
			SendRecvMultiThread(begin,end,out_begin,iface,timeout,retry,num_threads);

	}

	/* This function is executed by a thread */
	template<typename FowardIter, typename OutputIter>
	void* SocketSendRecvThreadIterator(void* thread_arg) {

		/* Cast the argument */
		ThreadData<FowardIter,OutputIter>* pair = static_cast<ThreadData<FowardIter,OutputIter> *>(thread_arg);

		/* Assign the values */
		int num_threads = pair->num_threads;
		FowardIter begin = pair->beginIterator;
		OutputIter out_begin = pair->beginOutput;
		size_t total = pair->total;
		int retry = pair->retry;
		double timeout = pair->timeout;
		/* Count packets */
		size_t count = pair->start_count;
		while(count < total) {
			(*begin)->SocketSendRecvPtr(pair->sd,pair->iface,timeout,retry," ",(*out_begin));
			count += num_threads;
			if(count > total) break;
			advance(begin,num_threads);
			advance(out_begin,num_threads);
		}

		delete pair;

		/* Call pthread exit */
		pthread_exit(NULL);
	}

	/* A multithreaded Send function */
	template<typename FowardIter, typename OutputIter>
	void SocketSendRecvMultiThread(int sd,FowardIter begin, FowardIter end, OutputIter out_begin,
			                 const std::string& iface, double timeout, int retry, int num_threads) {
		/* Total number of packets */
		int total = distance(begin,end);
		if (total < num_threads) num_threads = total;

		/* Thread array */
		pthread_t* threads = new pthread_t[num_threads];

		/* Do the work on each packet */
		for(int i = 0 ; i < num_threads ; i++) {
			/* Create a pair structure */
			ThreadData<FowardIter,OutputIter>* pair = new ThreadData<FowardIter,OutputIter>;

			/* Start value on the container */
			pair->beginIterator = begin;
			advance(pair->beginIterator,i);
			/* Start value of output iterator */
			pair->beginOutput = out_begin;
			advance(pair->beginOutput,i);
			/* Start value for the counter */
			pair->start_count = i;
			/* Put the number of threads */
			pair->num_threads = num_threads;
			/* Put the size of the container */
			pair->total = total;
			/* Set the arguments for the SendRecv function */
			pair->iface = iface;
			/* Number of times the packet is sent */
			pair->retry = retry;
			/* Timeout */
			pair->timeout = timeout;
			/* Save socket */
			pair->sd = sd;

			void* thread_arg = static_cast<void *>(pair);

			int rc = pthread_create(&threads[i], NULL, SocketSendRecvThreadIterator<FowardIter,OutputIter>, thread_arg);

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

	/* Send a range of packets defined with forward iterators */
	template<typename FowardIter, typename OutputIter>
	void SocketSendRecv(int sd, FowardIter begin, FowardIter end, OutputIter out_begin,
			      const std::string& iface = "", double timeout = 1, int retry = 3, int num_threads = 0) {

		if(num_threads == 0) {
				while(begin != end) {
					(*begin)->SocketSendRecvPtr(sd,iface,timeout,retry," ",(*out_begin));
					begin++;
					out_begin++;
				}
		} else
			SocketSendRecvMultiThread(sd,begin,end,out_begin,iface,timeout,retry,num_threads);

	}

	/* +++++++++++++++++++ Pcap dumpers and readers +++++++++++++++++++++ */

	/* Pcap dumper */
	template<typename FowardIter>
	void DumpPcap(FowardIter begin, FowardIter end, const std::string& filename) {

		/* We suppose that all the packets begin with the same layer */
		Layer* first = *((*begin)->begin());

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

	    OpenPcapDumper(link_type, filename, pd, pdumper);

		while(begin != end) {
			/* pcap header */
			struct pcap_pkthdr header;
			header.ts = (*begin)->GetTimestamp();
			size_t size = (*begin)->GetSize();
			header.len = size;
			header.caplen = size;
			DumperPcap(pdumper,&header,(*begin)->GetRawPtr());
	        begin++;
		}

		ClosePcapDumper(pd,pdumper);

	}

	/* Pcap reader */

	template<class Seq>
	struct ThreadReadData {
		int link_type;
		Seq* pck_container;
	};

	template<class Pointer>
	inline void PutPacket(size_t len, int link_type, const u_char* packet, Pointer& pck_ptr) {
		/* New packet on the heap */
		pck_ptr = Pointer(new Packet);

		/* Construct the packet */
		if(link_type == DLT_RAW)
			pck_ptr->PacketFromIP(packet,len);
		else
			pck_ptr->PacketFromLinkLayer(packet, len,link_type);
	}

	/* Callback function to process a packet when readed */
	template<class Seq>
	static void process_thread (u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {

		/* Argument for packet handling */
		ThreadReadData<Seq>* total_arg = reinterpret_cast<ThreadReadData<Seq>*>(user);

		/* Get the container */
		Seq* cont = total_arg->pck_container;
		/* Get size of the vector */
		size_t current_size = cont->size();
		cont->resize(current_size + 1);

		/* Push this packet into the container */
		PutPacket(header->len, total_arg->link_type, packet, cont->back());
		cont->back()->SetTimestamp(header->ts);
	}

	template<class Seq>
	void ReadPcap(Seq* pck_container, const std::string& filename, const std::string& filter = "") {
		/* Handle for the opened pcap session */
		pcap_t *handle;
		/* Type of link layer of the interface */
		int link_type;

		OpenOffPcap(&link_type,handle,filename,filter);

		/* Prepare the data */
		ThreadReadData<Seq> rd;
		rd.link_type = link_type;
		rd.pck_container = pck_container;

		u_char* arg = reinterpret_cast<u_char*>(&rd);

		LoopPcap(handle,-1,process_thread<Seq>,arg);

		ClosePcap(handle);
	}

	void ReadPcap(const std::string& filename, Packet::PacketHandler PacketHandlerFunction, void* user = 0, const std::string& filter = "");

	/* ---------------- Send an Receive functions (wrappers for backward compatibility) -------------- */

	/* DEPRECATED functions */

	typedef std::vector<Packet*> PacketContainer;

	/* Dump packet container on a pcap file */
	void DumpPcap(const std::string& filename, PacketContainer* pck_container);

	/* Read a pcap file */
	PacketContainer* ReadPcap(const std::string& filename, const std::string& filter = "");

	/* Send and Receive a container of packet - Multithreading */
	PacketContainer* SendRecv(PacketContainer* pck_container, const std::string& iface = "",
			                  int num_threads = 16, double timeout = 1, int retry = 3);

	/* Send a container of packet - Multithreading */
	void Send(PacketContainer* pck_container, const std::string& iface = "", int num_threads = 16);
}

#endif /* PACKETCONTAINER_H_ */
