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


#include "TCPConnection.h"
#include "IPResolver.h"
#include <ctime>

using namespace std;
using namespace Crafter;

std::string TCPConnection::TCPStatus[] = {
		"LISTEN",
		"SYN_SENT",
		"SYN_RECEIVED",
		"ESTABLISHED",
		"FIN_WAIT_1",
		"FIN_WAIT_2",
		"CLOSE_WAIT",
		"CLOSING",
		"LAST_ACK",
		"TIME_WAIT",
		"CLOSED"
};

namespace Crafter {
	void* ConnectHandler(void* thread_arg);
	void PckHand(Crafter::Packet* sniff_packet, void* user);
}

void TCPBuffer::ReassembleData(Payload& buffer) {
	if(seq_table.size() > 0) {
		/* Add each payload into the buffer */
		map<uint64_t,Payload>::iterator it = seq_table.begin();

		/* Set the payload */
		buffer.SetPayload((*it).second);
//		printf("%lu\n",(*it).first);
//		printf("@@@@@@@\n");
//		(*it).second.PrintChars();
//		printf("\n@@@@@@@\n");
		/* Increment one to the iterator */
		it++;

		/* Now add all the payloads into the buffer */
		for(; it != seq_table.end() ; it++) {
			buffer.AddPayload((*it).second);
//			printf("%lu\n",(*it).first);
//			printf("@@@@@@@\n");
//			(*it).second.PrintChars();
//			printf("\n@@@@@@@\n");
		}
	} else {
		buffer.Clear();
	}
}

void TCPBuffer::Add(word seq, const Payload& payload) {
	/* 64 bit sequence number */
	uint64_t long_seq = seq;
	uint64_t const_long = 4294967295ul;
	const_long++;
	/* Check if the seq number is lower than first_seq */
	if (long_seq < first_seq)
		long_seq += const_long;

	/* Find the sequence number in the table */
	map<uint64_t,Payload>::iterator it = seq_table.find(long_seq);

	/* Check if the segment is not a duplicated */
	if(it == seq_table.end() && long_seq > psh_seq)
		/* Push the payload into the table */
		seq_table[long_seq] = payload;
}

byte TCPBuffer::Push(word seq, Crafter::Payload& buffer) {
	/* 64 bit sequence number */
	uint64_t long_seq = seq;
	uint64_t const_long = 4294967295ul;
	const_long++;

	/* Check if the seq number is lower than first_seq */
	if (long_seq < first_seq)
		long_seq += const_long;

	/* Check if the push segment is not duplicated */
	if(long_seq > psh_seq) {

		/* Reassembles data */
		ReassembleData(buffer);

		/* Clean the table */
		seq_table.clear();

		/* Set the last push sequence number */
		psh_seq = long_seq;

		return 1;
	}

	return 0;
}

/* Default packet handling function */
void Crafter::PckHand(Packet* sniff_packet, void* user) {
	TCPConnection* conex = static_cast<TCPConnection*>(user);

	if(conex->hold_flag) return;

	/* Lock mutex */
    pthread_mutex_lock (&conex->mutex);

	/* Get the TCP layer from the packet */
	TCP* tcp_header = GetTCP(*sniff_packet);

	/* If we receive an ACK (most probable thing) */
	if(tcp_header->GetACK()) {

		if(!conex->sync_flag) {
			conex->ack = tcp_header->GetSeqNumber();
			conex->sync_flag = 1;
			pthread_cond_signal(&conex->threshold_cv);
			conex->tcp_buffer.SetInitialSeq(conex->ack);
		}

		/* Update sequence number */
		conex->seq = tcp_header->GetAckNumber();

		/* Get the payload and print on stdout */
		RawLayer* payload = GetRawLayer(*sniff_packet);
		size_t nbytes = 0;

		/* Get flags */
		word flags = tcp_header->GetFlags();

		/* Check if we receive another flag */
		if(flags == (TCP::ACK | TCP::SYN)) {

			/* If the other side doesn't receive our ACK, send it again */
			if (conex->status == TCPConnection::SYN_RECEIVED) {
				/* ... and send another ACK packet */
				TCP* tcp_local_header = GetTCP(conex->tcp_packet);

				/* Set TCP data, the other header remains the same */
				tcp_local_header->SetAckNumber(conex->ack);
				tcp_local_header->SetSeqNumber(conex->seq);
				tcp_local_header->SetFlags(TCP::ACK);
				/* Send the packet */
				conex->tcp_packet.Send(conex->iface);
			}

			/* If we just already send a SYN request */
			if (conex->status == TCPConnection::SYN_SENT) {
				/* Sum one to the ack number */
				conex->ack = tcp_header->GetSeqNumber() + 1;

				/* ... and send another ACK packet */
				TCP* tcp_local_header = GetTCP(conex->tcp_packet);

				/* Set TCP data, the other header remains the same */
				tcp_local_header->SetAckNumber(conex->ack);
				tcp_local_header->SetSeqNumber(conex->seq);
				tcp_local_header->SetFlags(TCP::ACK);
				/* Send the packet */
				conex->tcp_packet.Send(conex->iface);

				/* Change status of the connection */
				conex->status = TCPConnection::SYN_RECEIVED;
				conex->PrintStatus();
				conex->tcp_packet.HexDump();
				conex->tcp_packet.Print();

				pthread_cond_signal(&conex->threshold_cv);
			}

		} if (payload) {

				conex->tcp_buffer.Add(tcp_header->GetSeqNumber(),payload->GetPayload());

				nbytes += payload->GetSize();

				/* We should update ack number... */
				conex->ack = tcp_header->GetSeqNumber() + nbytes;

				/* ...and send another ACK packet */
				TCP* tcp_local_header = GetTCP(conex->tcp_packet);

				/* Set TCP data, the other header remains the same */
				tcp_local_header->SetAckNumber(conex->ack);
				tcp_local_header->SetSeqNumber(conex->seq);
				tcp_local_header->SetFlags(TCP::ACK);

				conex->tcp_packet.Send(conex->iface);



		} if(tcp_header->GetPSH()) {

			/* Print the buffer and release it */
			if(conex->tcp_buffer.Push(tcp_header->GetSeqNumber(),conex->buffer)) {

				/* Set the read flag to zero and signal the PSH action */
				conex->read_flag = 1;
				pthread_cond_signal(&conex->threshold_cv);

				if(conex->read_handle == 0) {
					/* Default behaviour, print the payload to stdout */
					conex->buffer.PrintChars();
					//cout << tcp_header->GetSeqNumber() << endl;
				} else {
					/* Execute the handler function */
					//pthread_mutex_unlock (&conex->mutex);
					//printf("%ul\n", tcp_header->GetSeqNumber());
					//cout << "++++" << tcp_header->GetSeqNumber() << "++++" << endl;
					conex->read_handle(conex->buffer,conex->read_handle_arg);
					//pthread_mutex_lock (&conex->mutex);
				}
			}

		}

		if(tcp_header->GetFIN()) {

			/* We should update ack number... */
			conex->ack++;
			/* ...and send another ACK packet */
			TCP* tcp_local_header = GetTCP(conex->tcp_packet);

			if ((conex->status == TCPConnection::ESTABLISHED)) {

				/* Set TCP data, the other header remains the same */
				tcp_local_header->SetAckNumber(conex->ack);
				tcp_local_header->SetSeqNumber(conex->seq);
				tcp_local_header->SetFlags(TCP::ACK);

				conex->tcp_packet.Send(conex->iface);

				conex->status = TCPConnection::CLOSE_WAIT;
				conex->PrintStatus();
			}

			if(conex->status == TCPConnection::FIN_WAIT_2 || conex->status == TCPConnection::FIN_WAIT_1) {
				//cout << tcp_header->GetSeqNumber() << endl;
				//sleep(10);
				/* Set TCP data, the other header remains the same */
				tcp_local_header->SetAckNumber(conex->ack);
				tcp_local_header->SetSeqNumber(conex->seq);
				tcp_local_header->SetFlags(TCP::ACK);

				conex->tcp_packet.Send(conex->iface);

				conex->status = TCPConnection::CLOSED;
				conex->PrintStatus();
				pthread_cond_signal(&conex->threshold_cv);
				conex->sync_flag = 0;

				/* Unlock mutex */
				pthread_mutex_unlock (&conex->mutex);

				pthread_exit(NULL);
			}

			if(conex->status == TCPConnection::LAST_ACK) {
				conex->status = TCPConnection::CLOSED;
				conex->PrintStatus();
				pthread_cond_signal(&conex->threshold_cv);

				conex->sync_flag = 0;

				/* Unlock mutex */
				pthread_mutex_unlock (&conex->mutex);

				pthread_exit(NULL);
			}


		  /* Set send flag to one */
		} if (!conex->send_flag && tcp_header->GetAckNumber() == conex->next_seq) {
			conex->send_flag = 1;
			pthread_cond_signal(&conex->threshold_cv);
		}

		if(flags == TCP::ACK) {

			if (conex->status == TCPConnection::FIN_WAIT_1) {
				conex->status = TCPConnection::FIN_WAIT_2;
				conex->PrintStatus();
			}

			if (conex->status == TCPConnection::LAST_ACK) {

				conex->status = TCPConnection::CLOSED;
				conex->PrintStatus();
				pthread_cond_signal(&conex->threshold_cv);
				conex->sync_flag = 0;

				/* Unlock mutex */
				pthread_mutex_unlock (&conex->mutex);
				/* Exit thread */
				pthread_exit(NULL);
			}

		}

	}

	/* Unlock mutex */
	pthread_mutex_unlock (&conex->mutex);
}

void* Crafter::ConnectHandler(void* thread_arg) {
	/* Cast pointer*/
	TCPConnection* conex = static_cast<TCPConnection*>(thread_arg);

    pthread_mutex_lock (&conex->mutex);

	string src_ip = conex->src_ip;
	string dst_ip = conex->dst_ip;
	short_word src_port = conex->src_port;
	short_word dst_port = conex->dst_port;
	string iface = conex->iface;

	/* ---- Set the filter ---- */

	/* IP stuff */
	string filter = "tcp and host " + dst_ip + " and host " + src_ip;
	/* TCP stuff */
	filter += " and dst port " + StrPort(src_port) + " and src port " + StrPort(dst_port);

	//cout << filter << endl;

	/* Launch the snnifer */
	Sniffer sniff(filter,iface,PckHand);

	/* Signal the threshold... */
	pthread_cond_signal(&conex->threshold_cv);
	/* ...and unlock the threshold */
	pthread_mutex_unlock(&conex->mutex);

	/* Start capturing */
	sniff.Capture(-1,thread_arg);

	/* Get connection data */
	return 0;
}

TCPConnection::TCPConnection(const string& src_ip, const string& dst_ip, short_word src_port,
		                     short_word dst_port, const std::string& iface, short_word state) :
		                     src_ip(src_ip), dst_ip(dst_ip), src_port(src_port), dst_port(dst_port), iface(iface) {
	/* Set seq number */
	seq = 0;
	next_seq = 0;

	/* Set ack number */
	ack = 0;

	/* Init mutex and cond variable */
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init (&threshold_cv, NULL);

    /* Now init the headers */
    IPLayer* ip_header;

    if(validateIpv6Address(src_ip))
    	ip_header = new IPv6;
    else
    	ip_header = new IP;

    ip_header->SetSourceIP(src_ip);
    ip_header->SetDestinationIP(dst_ip);
    TCP tcp_header;
    tcp_header.SetSrcPort(src_port);
    tcp_header.SetDstPort(dst_port);
    RawLayer raw_header;
    raw_header.SetPayload(" ");
    /* And push to the global instance of the buffer packet */
    tcp_packet.PushLayer(*ip_header);
    tcp_packet.PushLayer(tcp_header);
    /* Also push the data into the send buffer (this include a raw layer) */
    tcp_send_packet.PushLayer(*ip_header);
    tcp_send_packet.PushLayer(tcp_header);
    tcp_send_packet.PushLayer(raw_header);

    delete ip_header;

    /* Set to zero the send flag */
    send_flag = 0;

    /* Set to zero the sync flag, by default the connection in not synchronized */
    sync_flag = 0;

    /* Set the read flag to zeor, by default there is nothing to read */
    read_flag = 0;

    /* Set the HOld flag to zero */
    hold_flag = 0;

    /* Set to zero the Read Handler data */
    read_handle = 0;
    read_handle_arg = 0;

    /* By default, the connection is set to established */
    status = state;
    PrintStatus();
    if(status != CLOSED)
		/* Spawn the sniffer */
		SpawnSniffer();
}

void TCPConnection::SpawnSniffer() {
    /* Cast arg */
	void* thread_arg = static_cast<void*>(this);

	/* Spawn thread */
	pthread_create(&thread_id, 0, &ConnectHandler, thread_arg);
	/* Detach thread */
	pthread_detach(thread_id);

	/* Wait for the sniffer */
    pthread_mutex_lock (&mutex);
    pthread_cond_wait(&threshold_cv, &mutex);
    pthread_mutex_unlock (&mutex);
}

void TCPConnection::Sync(word _seq) {

	/* Spawn a sniffer if the connection was closed */
	if(status == CLOSED) {

		SpawnSniffer();

		pthread_mutex_lock (&mutex);

		/* Update sequence number */
		seq = _seq;

		/* Get a random sequence number, if the user don't provide one */
		if(!seq)
			seq = RNG32();

		/* Get TCP header */
		TCP* tcp_local_header = GetTCP(tcp_packet);

		/* Set TCP data, the other header remains the same */
		tcp_local_header->SetSeqNumber(seq);
		tcp_local_header->SetFlags(TCP::SYN);

		/* Update connection status */
		status = SYN_SENT;
		PrintStatus();
		while(status == SYN_SENT) {

			/* Send the packet */
			tcp_packet.Send(iface);

			/* Wait two seconds to send the data again */
			clock_gettime(CLOCK_REALTIME, &tm);
			tm.tv_sec += 2;

			pthread_cond_timedwait(&threshold_cv,&mutex,&tm);

		}

		/* Set the connection as established */
		status = TCPConnection::ESTABLISHED;
		PrintStatus();
		pthread_mutex_unlock (&mutex);

	} else {
		/* Block until the sniffer synchronizes the seq and ack numbers */
		pthread_mutex_lock (&mutex);
		while(!sync_flag) pthread_cond_wait(&threshold_cv,&mutex);
		pthread_mutex_unlock (&mutex);
	}

}

void TCPConnection::Send(const byte* buffer, size_t size) {
	if(status == ESTABLISHED || status == CLOSE_WAIT) {
	    pthread_mutex_lock (&mutex);

		/* ...and send another ACK packet */
		TCP* tcp_local_header = GetTCP(tcp_send_packet);

		/* Set TCP data, the other header remains the same */
		tcp_local_header->SetAckNumber(ack);
		tcp_local_header->SetSeqNumber(seq);
		tcp_local_header->SetFlags(TCP::PSH | TCP::ACK);

		/* Get the raw layer */
		RawLayer* payload = GetRawLayer(tcp_send_packet);

		/* Set the payload */
		payload->SetPayload(buffer,size);

		/* Set send flag to zero */
		send_flag = 0;
		next_seq = seq + payload->GetSize();

		while (!send_flag) {

			tcp_send_packet.Send(iface);

			/* Wait two seconds to send the data again */
			clock_gettime(CLOCK_REALTIME, &tm);
			tm.tv_sec += 2;

			pthread_cond_timedwait(&threshold_cv,&mutex,&tm);
		}

		pthread_mutex_unlock (&mutex);

	}
}

void TCPConnection::Send(const char* buffer) {
	if(status == ESTABLISHED || status == CLOSE_WAIT) {

		pthread_mutex_lock (&mutex);

		/* ...and send another ACK packet */
		TCP* tcp_local_header = GetTCP(tcp_send_packet);

		/* Set TCP data, the other header remains the same */
		tcp_local_header->SetAckNumber(ack);
		tcp_local_header->SetSeqNumber(seq);
		tcp_local_header->SetFlags(TCP::PSH | TCP::ACK);

		/* Get the raw layer */
		RawLayer* payload = GetRawLayer(tcp_send_packet);

		/* Set the payload */
		payload->SetPayload(buffer);

		/* Set send flag to zero */
		send_flag = 0;
		next_seq = seq + payload->GetSize();

		while (!send_flag) {

			tcp_send_packet.Send(iface);

			/* Wait two seconds to send the data again */
			clock_gettime(CLOCK_REALTIME, &tm);
			tm.tv_sec += 2;

			pthread_cond_timedwait(&threshold_cv,&mutex,&tm);

		}

		pthread_mutex_unlock (&mutex);

	}
}

byte TCPConnection::Read(Payload& payload) {
	pthread_mutex_lock (&mutex);

	byte read_status = (status == ESTABLISHED || status == FIN_WAIT_1 || status == FIN_WAIT_2);

	while (!read_flag && read_status) {

		/* Wait two seconds to send the data again */
		clock_gettime(CLOCK_REALTIME, &tm);
		tm.tv_sec += 2;

		pthread_cond_timedwait(&threshold_cv,&mutex,&tm);

	}

	pthread_mutex_unlock (&mutex);

	if( read_flag && read_status ) {
		payload = buffer;
		read_flag = 0;

		return 1;
	}

	read_flag = 0;

	return 0;

}

void TCPConnection::Close() {
	if(status == ESTABLISHED) {
		pthread_mutex_lock (&mutex);

		/* ...and send another ACK packet */
		TCP* tcp_local_header = GetTCP(tcp_packet);

		/* Set TCP data, the other header remains the same */
		tcp_local_header->SetAckNumber(ack);
		tcp_local_header->SetSeqNumber(seq);
		tcp_local_header->SetFlags(TCP::FIN | TCP::ACK);

		tcp_packet.Send(iface);

		/* Change the status to FIN_WAIT_1 */
		status = FIN_WAIT_1;
		PrintStatus();
		pthread_mutex_unlock (&mutex);
	}
	if(status == CLOSE_WAIT) {
		pthread_mutex_lock (&mutex);

		/* ...and send another ACK packet */
		TCP* tcp_local_header = GetTCP(tcp_packet);

		/* Set TCP data, the other header remains the same */
		tcp_local_header->SetAckNumber(ack);
		tcp_local_header->SetSeqNumber(seq);
		tcp_local_header->SetFlags(TCP::FIN | TCP::ACK);

		tcp_packet.Send(iface);

		/* Change the status to FIN_WAIT_1 */
		status = LAST_ACK;
		PrintStatus();
		pthread_mutex_unlock (&mutex);
	}

	/* Wait here until the connection is closed... There is nothing else to do */
	pthread_mutex_lock (&mutex);
	while(status != CLOSED) pthread_cond_wait(&threshold_cv, &mutex);
	pthread_mutex_unlock (&mutex);

	sync_flag = 0;

}

void TCPConnection::Reset() {
	/* Kill the thread */
	pthread_cancel(thread_id);

    pthread_mutex_lock (&mutex);

	/* ...and send another ACK packet */
	TCP* tcp_local_header = GetTCP(tcp_packet);

	/* Set TCP data, the other header remains the same */
	tcp_local_header->SetAckNumber(0);
	tcp_local_header->SetSeqNumber(seq);
	tcp_local_header->SetFlags(TCP::RST);

	tcp_packet.Send(iface);

	status = CLOSED;
	PrintStatus();
	sync_flag = 0;

	pthread_mutex_unlock (&mutex);
}

TCPConnection::~TCPConnection() {
	/* Close thread */
	if(status != CLOSED) {
		pthread_cancel(thread_id);
	}

	/* Destroy condition variable */
	pthread_cond_destroy(&threshold_cv);

	/* Destroy mutex */
	pthread_mutex_destroy(&mutex);
}
