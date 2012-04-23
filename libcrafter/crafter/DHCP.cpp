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

using namespace std;
using namespace Crafter;

/* Destination MAC address byte fields names */
const string client_ether_fields[DHCP::n_ether_bytes] =
                                                  {
                                                    "ClientMAC1",
		                                            "ClientMAC2",
		                                            "ClientMAC3",
		                                            "ClientMAC4",
		                                            "ClientMAC5",
		                                            "ClientMAC6"
                                                   };

void DHCP::MacStringToFields(const std::string& mac_address) {
	size_t ipos = 0;

	for(int i = 0 ; i < n_ether_bytes ; i++) {

		size_t epos = mac_address.find_first_of(":",ipos);
		string ether_byte = mac_address.substr(ipos,2);

		char* endptr;

		word byte_value = strtoul(ether_byte.c_str(),&endptr,16);
		SetFieldValue<word>(client_ether_fields[i],byte_value);

		ipos = epos + 1;
	}
}

/* Get values of each field an update MAC address */
std::string DHCP::MacFieldsToString() {
	string mac;
	int i = 0;
	char str[3] = {0};

	for(i = 0 ; i < n_ether_bytes ; i++) {
		short_word dst = GetFieldValue<word>(client_ether_fields[i]);;
		sprintf(str,"%.2x",dst);
		if (i < n_ether_bytes - 1)
			mac += string(str)+":";
		else
			mac += string(str);
	}

	return mac;
}

DHCP::DHCP() {
	/* Allocate bytes */
	allocate_bytes(240);
	/* Name of the protocol represented by this layer */
	SetName("DHCP");
	/* Set the protocol ID */
	SetprotoID(0xfff4);

	/* Creates field information for the layer */
	DefineProtocol();

	/* Always set default values for fields in a layer */
	SetOperationCode(0);
	SetHardwareType(1);
	SetHardwareLength(6);
	SetHopCount(0);
	SetTransactionID(0);
	SetNumberOfSeconds(0);
	SetFlags(0x8000);
	SetClientIP("0.0.0.0");
	SetYourIP("0.0.0.0");
	SetServerIP("0.0.0.0");
	SetGatewayIP("0.0.0.0");
	SetClientMAC("ff:ff:ff:ff:ff:ff");
	ServerHostName = "";
	BootFileName = "";
}

void DHCP::DefineProtocol() {
	define_field("OperationCode",new NumericField(0,0,7));

	/* TODO - For now, just MAC addresses */
	define_field("HardwareType",new NumericField(0,8,15));
	define_field("HardwareLength",new NumericField(0,16,23));

	define_field("HopCount",new NumericField(0,24,31));
	define_field("TransactionID",new HexField(1,0,31));
	define_field("NumberOfSeconds",new HexField(2,0,15));
	define_field("Flags",new NumericField(2,16,31));
	define_field("ClientIP",new IPAddress(3,0,31));
	define_field("YourIP",new IPAddress(4,0,31));
	define_field("ServerIP",new IPAddress(5,0,31));
	define_field("GatewayIP",new IPAddress(6,0,31));
	define_field("ClientMAC1",new NumericField(7,0,7));
	define_field("ClientMAC2",new NumericField(7,8,15));
	define_field("ClientMAC3",new NumericField(7,16,23));
	define_field("ClientMAC4",new NumericField(7,24,31));
	define_field("ClientMAC5",new NumericField(8,0,7));
	define_field("ClientMAC6",new NumericField(8,8,15));
}

void DHCP::Craft() {
	/* 34 byte to reach the zero padding */
	size_t zero_pad_macaddr = 34;
	/* 44 bytes to reach the server host name */
	size_t servername_shift = 44;
	/* 108 bytes to reach the file boot name*/
	size_t filename_shift = 108;
	/* 236 bytes to reach the Magic Cookie*/
	size_t magicookie_shift = 236;

	/* Set the zero padding */
	/* TODO - For now, just MAC addresses */
	memset(raw_data + zero_pad_macaddr,0,magicookie_shift-zero_pad_macaddr);

	/* Copy the server host name into the data buffer */
	byte* server_ptr = raw_data + servername_shift;
	for(size_t i = 0; (i < ServerHostName.size()) && (i < (filename_shift - servername_shift)) ; i++)
		server_ptr[i] = ServerHostName[i];

	/* Copy the boot file name into the data buffer */
	byte* boot_ptr = raw_data + filename_shift;
	for(size_t i = 0; (i < BootFileName.size()) && (i < (magicookie_shift - filename_shift)) ; i++)
		boot_ptr[i] = BootFileName[i];

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

void DHCP::LibnetBuild(libnet_t* l) {
	/* Get the payload */
	size_t payload_size = GetPayloadSize();
	byte* payload;

	if (payload_size) {
		payload = new byte[payload_size];
		GetPayload(payload);
	} else
		payload = 0;

	/* IP addresses */
	in_addr_t cip = inet_addr(GetClientIP().c_str());
	in_addr_t yip = inet_addr(GetYourIP().c_str());
	in_addr_t sip = inet_addr(GetServerIP().c_str());
	in_addr_t gip = inet_addr(GetGatewayIP().c_str());
	/* Client MAC address */
	int r;
	u_int8_t* macaddr = libnet_hex_aton(ClientMAC.c_str(),&r);
	u_int8_t* chaddr = new u_int8_t[16];
	memset(chaddr,0,16);
	memcpy(chaddr,macaddr,6);

	/* Server host name and boot file */
	/* 44 bytes to reach the server host name */
	size_t servername_shift = 44;
	/* 108 bytes to reach the file boot name*/
	size_t filename_shift = 108;
	/* Now write the data into de libnet context */
	int dhcp = libnet_build_dhcpv4 (
			  	                    GetOperationCode(),
				                    GetHardwareType(),
				                    GetHardwareLength(),
				                    GetHopCount(),
				                    GetTransactionID(),
				                    GetNumberOfSeconds(),
				                    GetFlags(),
				                    htonl(cip),
				                    htonl(yip),
				                    htonl(sip),
				                    htonl(gip),
				                    chaddr,
				                    raw_data + servername_shift,
				                    raw_data + filename_shift,
			                        payload,
								    payload_size,
								    l,
								    0
							      );

	/* In case of error */
	if (dhcp == -1) {
		PrintMessage(Crafter::PrintCodes::PrintError,
				     "DHCP::LibnetBuild()",
		             "Unable to build DHCP header: " + string(libnet_geterror (l)));
		exit (1);
	}

	if(payload)
		delete [] payload;

}

void DHCP::FromRaw(const RawLayer& raw_layer) {
	/* Get size of the raw layer */
	size_t data_size = raw_layer.GetSize();

	/* Copy all the data */
	byte* dhcp_data = new byte[data_size];
	raw_layer.GetData(dhcp_data);

	/* Create the header */
	PutData(dhcp_data);

	MacFieldsToString();

	/* 44 bytes to reach the server host name */
	size_t servername_shift = 44;
	/* 108 bytes to reach the file boot name*/
	size_t filename_shift = 108;
	/* 236 bytes to reach the Magic Cookie*/
	size_t magicookie_shift = 236;

	ServerHostName = string((const char *)(dhcp_data + servername_shift), filename_shift - servername_shift);
	BootFileName = string((const char *)(dhcp_data + filename_shift), magicookie_shift - filename_shift);

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

}

void DHCP::Print() const {

	cout << "< ";
	cout << name << " (" << dec << GetSize() << " bytes) " << ":: ";

	cout << "OperationCode = " << hex << "0x" << (unsigned int)GetOperationCode() << " ; ";
	cout << "HardwareType = " << hex << "0x" << (unsigned int)GetHardwareType() << " ; ";
	cout << "HardwareLength = " << hex << "0x" << (unsigned int)GetHardwareLength() << " ; ";
	cout << "HopCount = " << hex << "0x" << (unsigned int)GetHopCount() << " ; ";
	cout << "TransactionID = " << hex << "0x" << (unsigned int)GetTransactionID() << " ; ";
	cout << "NumberOfSeconds = " << dec << "0x" << GetNumberOfSeconds() << " ; ";
	cout << "Flags = " << hex << "0x" << (unsigned int)GetFlags() << " ; ";
	cout << "ClientIP = " << GetClientIP() << " ; ";
	cout << "YourIP = " << GetYourIP() << " ; ";
	cout << "ServerIP = " << GetServerIP() << " ; ";
	cout << "GatewayIP = " << GetGatewayIP() << " ; ";
	cout << "ClientMAC = " << GetClientMAC() << " ; ";
	cout << "BootFile = " << GetBootFile() << " ; ";
	cout << "ServerHostName = " << GetServerHostName() << " ; ";

	std::vector<DHCPOptions*>::const_iterator it_opt;

	cout << endl;
	for(it_opt = Options.begin() ; it_opt != Options.end() ; it_opt++)
		(*it_opt)->Print();

	cout << ">" << endl;

}

DHCP::~DHCP() {
	/* Delete the Options */
	std::vector<DHCPOptions*>::const_iterator it_opt;

	for(it_opt = Options.begin() ; it_opt != Options.end() ; it_opt++)
		delete (*it_opt);
}

