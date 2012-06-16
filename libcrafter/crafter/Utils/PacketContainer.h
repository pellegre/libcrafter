/*
 * PacketContainer.h
 *
 *  Created on: Jun 7, 2012
 *      Author: larry
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
	T fromString(const std::string& str) {
		std::istringstream s(str);
		T t;
		s >> t;
		return t;
	}

	template<typename T>
	std::string toString(const T& t) {
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
	};

	class PacketContainer : public std::vector<Packet*> {

		/* Sender functions */
		void SendMultiThread(const std::string& iface, int num_threads);
		void SendLoop(const std::string& iface);

		/* Sender and matcher functions */
		PacketContainer* SendRecvMultiThread(const std::string& iface, double timeout, int retry, int num_threads);
		PacketContainer* SendRecvLoop(const std::string& iface, double timeout, int retry);

	public:

		PacketContainer() { /* */ };
		PacketContainer(size_t n) : std::vector<Packet*>(n) { /* */ };

		/* Copy constructor */
		PacketContainer(const PacketContainer& cpy);
		/* Assignment operator */
		PacketContainer& operator=(const PacketContainer& right);

		/* Send the packets */
		void Send(const std::string& iface = "", int num_threads = 0);

		/* Send and Receive the container  */
		PacketContainer* SendRecv(const std::string& iface = "", double timeout = 1, int retry = 3, int num_threads = 0);

		/* Dump packet container on a pcap file */
		void DumpPcap(const std::string& filename);
		/* Read a pcap file */
		void ReadPcap(const std::string& filename, const std::string& filter = "");

		/*
		 * Delete all the pointer and clear the container
		 * This function should be used only in case the packets were allocated on the heap
		 */
		void ClearPackets();

		virtual ~PacketContainer() { /* */ };

	};

	/* +++++++++++++++++++ Clear Container +++++++++++++++++++++ */

	template<class Seq>
	void ClearContainer(Seq& seq) {
		typename Seq::iterator it = seq.begin();
		while (it != seq.end()) {
			delete (*it);
			it++;
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
		int retry = pair->retry;
		/* Count packets */
		size_t count = pair->start_count;
		while(count < total) {
			for(int i = 0 ; i < retry ; i++)
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
	void SendMultiThread(FowardIter begin, FowardIter end, const std::string& iface, int num_threads, int ntries) {
		/* Total number of packets */
		size_t total = distance(begin,end);
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
			/* Number of times the packet is sent */
			pair->retry = ntries;

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
	void Send(FowardIter begin, FowardIter end, const std::string& iface = "", int num_threads = 0, int ntries = 1) {
		if(num_threads == 0) {
			for(int i = 0 ; i < ntries ; i++) {
				while(begin != end) {
					(*begin)->Send(iface);
					begin++;
				}
			}
		}
		else
			SendMultiThread(begin,end,iface,num_threads,ntries);
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
		size_t total = distance(begin,end);
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

	/* +++++++++++++++++++ Pcap dumpers and readers +++++++++++++++++++++ */
}

#endif /* PACKETCONTAINER_H_ */
