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


#ifndef TCPCONNECTION_H_
#define TCPCONNECTION_H_

#include "../Crafter.h"
#include "CrafterUtils.h"

namespace Crafter {
	void* ConnectHandler(void* thread_arg);
	void PckHand(Crafter::Packet* sniff_packet, void* user);

	class TCPBuffer {

		/* A table that relates the sequence numbers and the data on the segment */
		std::map<uint64_t,Crafter::Payload> seq_table;

		/* First sequence number, which is saved when the object is created */
		uint64_t first_seq;

		/* Last sequence number which carries a PSH flag */
		uint64_t psh_seq;

		/* Function that reassembles the data in seq_table */
		void ReassembleData(Crafter::Payload& buffer);

	public:

		/* Constructor, set the initial seq number */
		TCPBuffer(word first_seq = 0) : first_seq(first_seq), psh_seq(0) { /* */ };

		/* Set initial sequence number */
		void SetInitialSeq(word seq) { first_seq = seq; };

		/* Get initial seq number */
		size_t GetInitialSeq() const { return first_seq; };

		/* Add a new segment into the table */
		void Add(word seq, const Crafter::Payload& payload);

		/*
		 * Reassemble the data in <buffer> only if seq > psh_seq
		 * If the function returns zero means that the PSH segment is
		 * duplicated. Else, means the data was pushed
		 */
		byte Push(word seq, Crafter::Payload& buffer);

		/* Destructor */
		virtual ~TCPBuffer() { /*  */ };

	};


	class TCPConnection {

		/* Function type that is called when a read occurs */
		typedef void ((*ReadHandler)(Payload&,void*));

		static std::string TCPStatus[];

		/* ++++ Connection Data Begin : This data defines univocally a connection ++++ */

		/* Source IP address */
		std::string src_ip;

		/* Destination IP address */
		std::string dst_ip;

		/* Source Port number */
		short_word src_port;

		/* Destination Port number */
		short_word dst_port;

		/* Sequence number */
		uint64_t seq;

		/* Expected Sequence number */
		uint64_t next_seq;

		/* Acknowledgment number */
		uint64_t ack;

		/* ++++ Connection Data End : This data defines univocally a connection ++++ */
		/* Sniffer used */
		Sniffer *sniff;

		/* Thread ID of the sniffer */
		pthread_t thread_id;

		/* Class Mutex variable */
		pthread_mutex_t mutex;

		/* Condition variable for signals */
		pthread_cond_t threshold_cv;

		/* Global packet, a buffer */
		Crafter::Packet tcp_packet;

		/* Global packet, a buffer for sending data (contains a payload) */
		Crafter::Packet tcp_send_packet;

		/* Interface */
		std::string iface;

		/* TCP Buffer for data reassembly */
		TCPBuffer tcp_buffer;

		/* Connection payload */
		Payload buffer;

		/* Connection status */
		short_word status;

		/* Send flag -- This flag is set to one if the receiver confirm with an ack our data*/
		byte send_flag;

		/* Sync flag, this is set to one one the connection in synchronized */
		byte sync_flag;

		/* Read flag, this is set to one when the buffer is ready for reading */
		byte read_flag;

		/*
		 * Hold flag, this is set to one if the connection is on a hold state. That means that the connections
		 * parameters aren't updated in spite of uncomming packets.
		 */
		byte hold_flag;

		/* Structure for timing */
		struct timespec tm;

		/* Read handle data */
		ReadHandler read_handle;
		void* read_handle_arg;

		/* Spawn a thread with the sniffer */
		void SpawnSniffer();

		/* Copy Constructor */
		TCPConnection(const TCPConnection& copy);
		/* Assignament operator */
		TCPConnection& operator=(const TCPConnection& right);

		/* Print status change of the connection */
		void PrintStatus() const{
			std::cout << "(" << src_ip << ":" << src_port << " ; " << dst_ip << ":" << dst_port << ") : " <<
					     "Status changed to --> " << TCPStatus[status-1] << std::endl;
		};

	public:
		/* ---- Connecion status (from RFC 793) ---- */

		/*
		    LISTEN - represents waiting for a connection request from any remote
			TCP and port. NOT SUPPORTED, yet... TODO if neccesary.
		*/
		static const short_word LISTEN = 1;

		/*
			SYN-SENT - represents waiting for a matching connection request
			after having sent a connection request.
		*/
		static const short_word SYN_SENT = 2;

		/*
			SYN-RECEIVED - represents waiting for a confirming connection
			request acknowledgment after having both received and sent a
			connection request.
		*/
		static const short_word SYN_RECEIVED = 3;

		/*
			ESTABLISHED - represents an open connection, data received can be
			delivered to the user.  The normal state for the data transfer phase
			of the connection.
		*/
		static const short_word ESTABLISHED = 4;

		/*
			FIN-WAIT-1 - represents waiting for a connection termination request
			from the remote TCP, or an acknowledgment of the connection
			termination request previously sent.
		*/
		static const short_word FIN_WAIT_1 = 5;

		/*
			FIN-WAIT-2 - represents waiting for a connection termination request
			from the remote TCP.
		*/
		static const short_word FIN_WAIT_2 = 6;

		/*
			CLOSE-WAIT - represents waiting for a connection termination request
			from the local user.
		*/
		static const short_word CLOSE_WAIT = 7;

		/*
			CLOSING - represents waiting for a connection termination request
			acknowledgment from the remote TCP.
		*/
		static const short_word CLOSING = 8;

		/*
			LAST-ACK - represents waiting for an acknowledgment of the
			connection termination request previously sent to the remote TCP
			(which includes an acknowledgment of its connection termination
			request).
		*/
		static const short_word LAST_ACK = 9;

		/*
			TIME-WAIT - represents waiting for enough time to pass to be sure
			the remote TCP received the acknowledgment of its connection
			termination request.
		*/
		static const short_word TIME_WAIT = 10;

		/*
			CLOSED - represents no connection state at all.
		*/
		static const short_word CLOSED = 11;

		friend void* Crafter::ConnectHandler(void* thread_arg);
		friend void Crafter::PckHand(Crafter::Packet* sniff_packet, void* user);

		/* Constructor of the class that defines the basic connections parameters (ack and seq are optionals) */
		TCPConnection(const std::string& src_ip, const std::string& dst_ip, short_word src_port, short_word dst_port,
					  const std::string& iface = "", short_word state = CLOSED);

		/* Sync connection (obtain seq and ack number for a new or an already established connection) */
		void Sync(word _seq = 0);

		/* Send data on buffer */
		void Send(const byte* buffer, size_t size);
		void Send(const char* buffer);

		/* Set a Read handler function */
		void SetReadHandler(ReadHandler read_handle, void* read_handle_arg) {
			this->read_handle = read_handle ; this->read_handle_arg = read_handle_arg;
		};
		/* Read function, put a payload after a PSH packet. If the connection is closed, the functions returns zero */
		byte Read(Payload& payload);

		/* Hold and unhold the connection */
		void Hold() { pthread_mutex_lock (&mutex); hold_flag = 1; pthread_mutex_unlock (&mutex);};
		void UnHold() { pthread_mutex_lock (&mutex); hold_flag = 0; pthread_mutex_unlock (&mutex);};

		/* Close nicely the connection (FIN/ACK) */
		void Close();

		/* Close badly the connection */
		void Reset();

		/* Get the status of the connection */
		byte GetStatus() const {return status;};

		virtual ~TCPConnection();
	};
}

#endif /* TCPCONNECTION_H_ */

