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

#include "DHCP.h"

using namespace Crafter;
using namespace std;

void DHCP::ReDefineActiveFields() {
}

void DHCP::Craft() {
	/* 236 bytes to reach the Magic Cookie*/
	size_t magicookie_shift = 236;
	/* Put the magic cookie */
	raw_data[magicookie_shift] = 0x63;
	raw_data[magicookie_shift + 1] = 0x82;
	raw_data[magicookie_shift + 2] = 0x53;
	raw_data[magicookie_shift + 3] = 0x63;

	std::vector<DHCPOptions*>::const_iterator it_opt;

	for(it_opt = Options.begin() ; it_opt != Options.end() ; it_opt++) {
		AddPayload((*it_opt)->GetData());
	}

	/* Put the end of options byte */
	byte padd = 0xff;
	AddPayload((const byte*)&padd,sizeof(byte));
}

/*
 * Adapted from dhcpdump code
 * http://dhcpdump.sourcearchive.com/documentation/1.8-2/dhcpdump_8c-source.html
 */
void DHCP::FromRaw(const RawLayer& raw_layer) {
	/* Get size of the raw layer */
	size_t data_size = raw_layer.GetSize();

	/* Copy all the data */
	byte* dhcp_data = new byte[data_size];
	raw_layer.GetData(dhcp_data);

	/* Create the header */
	PutData(dhcp_data);

	/* 236 bytes to reach the Magic Cookie*/
	size_t magicookie_shift = 236;

	/* Delete the Options */
	std::vector<DHCPOptions*>::const_iterator it_opt;

	for(it_opt = Options.begin() ; it_opt != Options.end() ; it_opt++)
		delete (*it_opt);
	Options.clear();

	byte* data = dhcp_data + magicookie_shift + 4;

	size_t j = 0 ;

	vector<string> ip_addr;
	int i = 0;
    while (j < data_size && data[j] != 255) {

		switch (data[j]) {

		default:
			Options.push_back(CreateDHCPOption(data[j],data + j + 2, data[j + 1]));
			break;

		case 0:           // pad
			break;

		case  1:    // Subnetmask
		case  3:    // Routers
		case 16:    // Swap server
		case 28:    // Broadcast address
		case 32:    // Router solicitation
		case 50:    // Requested IP address
		case 54:    // Server identifier
			ip_addr.clear();
			ip_addr.push_back(string(inet_ntoa( *((in_addr*)(data + j + 2)) )));
			Options.push_back(CreateDHCPOption(data[j],ip_addr));
			break;

		case 12:    // Hostname
		case 14:    // Merit dump file
		case 15:    // Domain name
		case 17:    // Root Path
		case 18:    // Extensions path
		case 40:    // NIS domain
		case 56:    // Message
		case 62:    // Netware/IP domain name
		case 64:    // NIS+ domain
		case 66:    // TFTP server name
		case 67:    // bootfile name
		case 60:    // Domain name
		case 86:    // NDS Tree name
		case 87:    // NDS context
			Options.push_back(CreateDHCPOption(data[j], string((char *)&data[j + 2], data[j + 1])) );
			break;

		case  4:    // Time servers
		case  5:    // Name servers
		case  6:    // DNS server
		case  7:    // Log server
		case  8:    // Cookie server
		case  9:    // LPR server
		case 10:    // Impress server
		case 11:    // Resource location server
		case 41:    // NIS servers
		case 42:    // NTP servers
		case 44:    // NetBIOS name server
		case 45:    // NetBIOS datagram distribution server
		case 48:    // X Window System font server
		case 49:    // X Window System display server
		case 65:    // NIS+ servers
		case 68:    // Mobile IP home agent
		case 69:    // SMTP server
		case 70:    // POP3 server
		case 71:    // NNTP server
		case 72:    // WWW server
		case 73:    // Finger server
		case 74:    // IRC server
		case 75:    // StreetTalk server
		case 76:    // StreetTalk directory assistance server
		case 85:    // NDS server
			ip_addr.clear();
			for (i = 0; i < data[j + 1] / 4; i++) {
				ip_addr.push_back(string(inet_ntoa( *((in_addr*)(data + j + 2 + i * 4)) )));
			}
			Options.push_back(CreateDHCPOption(data[j],ip_addr));
			break;

		case 13:    // bootfile size
		case 22:    // Maximum datagram reassembly size
		case 26:    // Interface MTU
		case 57:    // Maximum DHCP message size
			Options.push_back(CreateDHCPOption(data[j], *((short_word *)(data + j + 2)), DHCPOptions::SHORT));
			break;

		case 19:    // IP forwarding enabled/disable
		case 20:    // Non-local source routing
		case 23:    // Default IP TTL
		case 27:    // All subnets local
		case 29:    // Perform mask discovery
		case 30:    // Mask supplier
		case 31:    // Perform router discovery
		case 34:    // Trailer encapsulation
		case 36:    // Ethernet encapsulation
		case 37:    // TCP default TTL
		case 39:    // TCP keepalive garbage
		case 46:    // NetBIOS over TCP/IP node type
		case 52:    // Option overload
		case 53:    // DHCP message type
			Options.push_back(CreateDHCPOption(data[j], *((byte *)(data + j + 2)), DHCPOptions::BYTE));
			break;

		case  2:    // Time offset
		case 24:    // Path MTU aging timeout
		case 35:    // ARP cache timeout
		case 38:    // TCP keepalive interval
		case 51:    // IP address leasetime
		case 58:    // T1
		case 59:    // T2
			Options.push_back(CreateDHCPOption(data[j], *((word *)(data + j + 2)), DHCPOptions::WORD));
			break;
		}

		/*
		 * This might go wrong if a mallformed packet is received.
		 * Maybe from a bogus server which is instructed to reply
		 * with invalid data and thus causing an exploit.
		 * My head hurts... but I think it's solved by the checking
		 * for j<data_len at the begin of the while-loop.
		*/
		if (data[j]==0)         // padding
			j++;
		else
			j+=data[j + 1] + 2;
    }

    Craft();
}

void DHCP::PrintPayload(ostream& str) const {
	cout << "Payload = " << endl;

	std::vector<DHCPOptions*>::const_iterator it_opt;

	for(it_opt = Options.begin() ; it_opt != Options.end() ; it_opt++)
		(*it_opt)->Print();

}

void DHCP::ParseLayerData(ParseInfo* info) {
	const byte* data = info->raw_data + info->offset;

	size_t j = 0 ;

	vector<string> ip_addr;
	int i = 0;
    while (j < (info->total_size - info->offset - 4) && data[j] != 255) {

		switch (data[j]) {

		default:
			Options.push_back(CreateDHCPOption(data[j],data + j + 2, data[j + 1]));
			break;

		case 0:           // pad
			break;

		case  1:    // Subnetmask
		case  3:    // Routers
		case 16:    // Swap server
		case 28:    // Broadcast address
		case 32:    // Router solicitation
		case 50:    // Requested IP address
		case 54:    // Server identifier
			ip_addr.clear();
			ip_addr.push_back(string(inet_ntoa( *((in_addr*)(data + j + 2)) )));
			Options.push_back(CreateDHCPOption(data[j],ip_addr));
			break;

		case 12:    // Hostname
		case 14:    // Merit dump file
		case 15:    // Domain name
		case 17:    // Root Path
		case 18:    // Extensions path
		case 40:    // NIS domain
		case 56:    // Message
		case 62:    // Netware/IP domain name
		case 64:    // NIS+ domain
		case 66:    // TFTP server name
		case 67:    // bootfile name
		case 60:    // Domain name
		case 86:    // NDS Tree name
		case 87:    // NDS context
			Options.push_back(CreateDHCPOption(data[j], string((char *)&data[j + 2], data[j + 1])) );
			break;

		case  4:    // Time servers
		case  5:    // Name servers
		case  6:    // DNS server
		case  7:    // Log server
		case  8:    // Cookie server
		case  9:    // LPR server
		case 10:    // Impress server
		case 11:    // Resource location server
		case 41:    // NIS servers
		case 42:    // NTP servers
		case 44:    // NetBIOS name server
		case 45:    // NetBIOS datagram distribution server
		case 48:    // X Window System font server
		case 49:    // X Window System display server
		case 65:    // NIS+ servers
		case 68:    // Mobile IP home agent
		case 69:    // SMTP server
		case 70:    // POP3 server
		case 71:    // NNTP server
		case 72:    // WWW server
		case 73:    // Finger server
		case 74:    // IRC server
		case 75:    // StreetTalk server
		case 76:    // StreetTalk directory assistance server
		case 85:    // NDS server
			ip_addr.clear();
			for (i = 0; i < data[j + 1] / 4; i++) {
				ip_addr.push_back(string(inet_ntoa( *((in_addr*)(data + j + 2 + i * 4)) )));
			}
			Options.push_back(CreateDHCPOption(data[j],ip_addr));
			break;

		case 13:    // bootfile size
		case 22:    // Maximum datagram reassembly size
		case 26:    // Interface MTU
		case 57:    // Maximum DHCP message size
			Options.push_back(CreateDHCPOption(data[j], *((short_word *)(data + j + 2)), DHCPOptions::SHORT));
			break;

		case 19:    // IP forwarding enabled/disable
		case 20:    // Non-local source routing
		case 23:    // Default IP TTL
		case 27:    // All subnets local
		case 29:    // Perform mask discovery
		case 30:    // Mask supplier
		case 31:    // Perform router discovery
		case 34:    // Trailer encapsulation
		case 36:    // Ethernet encapsulation
		case 37:    // TCP default TTL
		case 39:    // TCP keepalive garbage
		case 46:    // NetBIOS over TCP/IP node type
		case 52:    // Option overload
		case 53:    // DHCP message type
			Options.push_back(CreateDHCPOption(data[j], *((byte *)(data + j + 2)), DHCPOptions::BYTE));
			break;

		case  2:    // Time offset
		case 24:    // Path MTU aging timeout
		case 35:    // ARP cache timeout
		case 38:    // TCP keepalive interval
		case 51:    // IP address leasetime
		case 58:    // T1
		case 59:    // T2
			Options.push_back(CreateDHCPOption(data[j], *((word *)(data + j + 2)), DHCPOptions::WORD));
			break;
		}

		/*
		 * This might go wrong if a mallformed packet is received.
		 * Maybe from a bogus server which is instructed to reply
		 * with invalid data and thus causing an exploit.
		 * My head hurts... but I think it's solved by the checking
		 * for j<data_len at the begin of the while-loop.
		*/
		if (data[j]==0)         // padding
			j++;
		else
			j+=data[j + 1] + 2;
    }

    Craft();

	info->offset = info->total_size;
	/* No more layers, default */
	info->top = 1;
}
