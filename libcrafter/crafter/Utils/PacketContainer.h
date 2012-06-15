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

	template<typename FowardIter>
	struct ThreadData {
		/* Container interators */
		FowardIter beginIterator;
		FowardIter endIterator;
		FowardIter outputIterator;
		/* Arguments for sending */
		std::string iface;
		int num_threads;
		double timeout;
		int retry;
	};

	/* Function called by a thread to send some packets */
	void* SendThread(void* thread_arg);

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

	/* Generic function template to apply a function to packet pointers */

	template<typename FowardIter, class T, class R, class A1>
	void ApplyPacketFunction(FowardIter begin, FowardIter end, R(T::*f)(A1), A1 a1) {
		while(begin != end) {
			((*begin)->*f)(a1);
			begin++;
		}
	}

	template<typename FowardIter, class T, class R, class A1, class A2>
	void ApplyPacketFunction(FowardIter begin, FowardIter end, R(T::*f)(A1, A2), A1 a1, A2 a2) {
		while(begin != end) {
			((*begin)->*f)(a1, a2);
			begin++;
		}
	}

	/* +++++++++++++++ Send the packets +++++++++++++++++++++ */

	/* This function is executed by a thread */
	template<typename FowardIter>
	void* SendThread(void* thread_arg) {

		/* Cast the argument */
		ThreadData<FowardIter>* pair = static_cast<ThreadData<FowardIter> *>(thread_arg);

		/* Assign the values */
		FowardIter begin = pair->beginIterator;
		FowardIter end = pair->endIterator;

		ApplyPacketFunction(begin,end,&Packet::Send,pair->iface);

		for (int i = start ; i < total ; i += num_threads)
			(*PktContainer)[i]->Send(pair->iface);

		delete pair;

		/* Call pthread exit */
		pthread_exit(NULL);
	}

	template<typename FowardIter>
	void SendMultiThread(FowardIter begin, FowardIter end, const std::string& iface, int num_threads) {
		/* Total number of packets */
		size_t total = distance(begin,end);
		if (total < num_threads) num_threads = total;

		/* Thread array */
		pthread_t* threads = new pthread_t[num_threads];

		/* Do the work on each packet */
		for(int i = 0 ; i < num_threads ; i++) {
			/* Create a pair structure */
			ThreadData<FowardIter>* pair = new ThreadData<FowardIter>;

			/* Start value on the container */
			pair->beginIterator = advance(begin,i);
			/* Put the number of threads */
			pair->num_threads = num_threads;
			/* Put the size of the container */
			pair->endIterator = end;

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

	template<typename FowardIter>
	void Send(FowardIter begin, FowardIter end, const std::string& iface = "", int num_threads = 0) {
		ApplyPacketFunction(begin,end,&Packet::Send,iface);
	}

}

#endif /* PACKETCONTAINER_H_ */
