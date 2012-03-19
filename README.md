LibCrafter: A high level API for C++ to forge and decode packet of most common 
            network protocols.
==================================

Libcrafter is a high level API for C++ designed to facilitate the creation and 
decoding of network packets. It is able to craft or decode packets of most 
common networks protocols, send them on the wire, capture them and match 
requests and replies.
It enables the creation of networking tools in a few lines with a interface 
very similar to [Scapy](http://www.secdev.org/projects/scapy/). 
A packet is  described as layers that you stack one upon the other. Fields of 
each layer have useful default values that you can overload.

The library is designed to be used in multithreaded programs where you can 
combine several tasks simultaneously. For example, you can easily design 
something that sniffs, mangles, and sends at the same time you are doing 
an ARP-Spoofing attack.
It also contains a very naive implementation of the TCP/IP stack (fragmentation 
is no handled yet) at user level that enables working with TCP streams. This 
facilitates the creation of tools for data injection on arbitrary connections 
and TCP/IP session hijacking. 

Examples
--------

LibCrafter is best explained through examples. The following source code
shows a "Hello World" program and some common methods for manipulating layers.

```c++
/*
* Compile the program:
* g++ hello.cpp -o hello -lcrafter
* sudo ./hello # You need root privileges for running the program
*/
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Init the library */
	InitCrafter();

	/* Create a Raw layer with some data on it... */
	RawLayer hello("Hello ");
	/* ...or a pointer */
	RawLayer* world = new RawLayer("World!");

	/* Create a packet to hold both layers */
	Packet packet;

	/* Push the first layer... */
	packet.PushLayer(hello);
	/* ... and finally the second one */
	packet.PushLayer(*world);

	/* You may print the packet to STDOUT... */
	cout << "[@] --- Print packet to STDOUT: " << endl;
	packet.Print();
	/* ...or hexdump it... */
	cout << "[@] --- HexDump the packet: " << endl;
	packet.HexDump();
	/* ...or print a hex string (so it's easy to include it on a C code, or whatever). */
	cout << "[@] --- Print RawString: " << endl;
	packet.RawString();

	/* And last but not least, you can write the packet on the wire :-) */
	packet.Send("ath0");

	/* Clean before exit */
	CleanCrafter();
	delete world;

	return 0;
}
}
```
  
This code shows how to forge a simple UDP packet with some arbitrary payload, 
and how to write it on the wire. Fields values that aren't provided by the user
(like checksums, lengths, etc) are automatically filled by the library with
corrects values. 

```c++
/*
* Compile the program:
* g++ udp.cpp -o udp -lcrafter
* sudo ./udp # You need root privileges for running the program
*/
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Init the library */
	InitCrafter();

	/* Set the interface */
	string iface = "ath0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);

	cout << "[@] My IP address is  : " << MyIP  << endl;

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);
	ip_header.SetDestinationIP("192.168.1.1");

	/* Create a UDP header */
	UDP udp_header;

	/* Set the source and destination ports */
	udp_header.SetSrcPort(1089);
	udp_header.SetDstPort(5436);

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("Some_UDP_Payload\n");

	/* Create a packet... */
	Packet packet = ip_header / udp_header / raw_header;

	/* Print before sending */
	cout << endl << "[@] Print before sending: " << endl;
	packet.Print();

	/* Send the packet, this would fill the missing fields (like checksum, length, etc) */
	packet.Send(iface);

	cout << endl;
	cout << "[+] ***************************************************** [+]" << endl;
	cout << endl;

	/* Print after sending, the packet is not the same. */
	cout << "[@] Print after sending: " << endl;
	packet.Print();

	/* The output is the same as before */
	//packet.HexDump();

	/* Clean before exit */
	CleanCrafter();

	return 0;
}
}
```
