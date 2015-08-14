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

#ifndef DHCPOPTIONS_H_
#define DHCPOPTIONS_H_

#include <iostream>
#include <vector>
#include <map>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../Payload.h"

/* -------- DHCP Options */

namespace Crafter {

	class DHCPOptions {

	protected:
		/* Data */
		Payload data;
		/* Code of the option */
		short_word code;
		/* A tag for know with what kind of option we are dealing */
		std::string tag;
		/* Fake size in case we want to create a malformed DHCP option */
		byte fake_size;

		/* Function that set the payload */
		virtual void SetPayload() = 0;

		/* Set internal field from the payload of the base class */
		virtual void SetFields() = 0;

		/* Function that clone a specific DHCP option */
		virtual DHCPOptions* Clone() const = 0;

		/* Function that prints the data */
		virtual void PrintData() const { data.Print(); };

		/* A global table that maps the code with a readable string */
		static std::map<int,std::string> code_table;
		/* A global table that maps the message type with a readable string */
		static std::map<int,std::string> mess_table;

	public:
		friend class DHCP;

		DHCPOptions(short_word code, std::string tag);

		/* DHCP options codes */
		static const word Pad = 0;
		static const word SubnetMask = 1;
		static const word TimeOffset = 2;
		static const word Router = 3;
		static const word TimeServer = 4;
		static const word NameServer = 5;
		static const word DomainServer = 6;
		static const word LogServer = 7;
		static const word QuotesServer = 8;
		static const word LPRServer = 9;
		static const word ImpressServer = 10;
		static const word RLPServer = 11;
		static const word Hostname = 12;
		static const word BootFileSize = 13;
		static const word MeritDumpFile = 14;
		static const word DomainName = 15;
		static const word SwapServer = 16;
		static const word RootPath = 17;
		static const word ExtensionFile = 18;
		static const word ForwardOn_Off = 19;
		static const word SrcRteOn_Off = 20;
		static const word PolicyFilter = 21;
		static const word MaxDGAssembly = 22;
		static const word DefaultIPTTL = 23;
		static const word MTUTimeout = 24;
		static const word MTUPlateau = 25;
		static const word MTUInterface = 26;
		static const word MTUSubnet = 27;
		static const word BroadcastAddress = 28;
		static const word MaskDiscovery = 29;
		static const word MaskSupplier = 30;
		static const word RouterDiscovery = 31;
		static const word RouterRequest = 32;
		static const word StaticRoute = 33;
		static const word Trailers = 34;
		static const word ARPTimeout = 35;
		static const word Ethernet = 36;
		static const word DefaultTCPTTL = 37;
		static const word KeepaliveTime = 38;
		static const word KeepaliveData = 39;
		static const word NISDomain = 40;
		static const word NISServers = 41;
		static const word NTPServers = 42;
		static const word VendorSpecific = 43;
		static const word NETBIOSNameSrv = 44;
		static const word NETBIOSDistSrv = 45;
		static const word NETBIOSNodeType = 46;
		static const word NETBIOSScope = 47;
		static const word XWindowFont = 48;
		static const word XWindowManager = 49;
		static const word AddressRequest = 50;
		static const word AddressTime = 51;
		static const word Overload = 52;
		static const word DHCPMsgType = 53;
		static const word DHCPServerId = 54;
		static const word ParameterList = 55;
		static const word DHCPMessage = 56;
		static const word DHCPMaxMsgSize = 57;
		static const word RenewalTime = 58;
		static const word RebindingTime = 59;
		static const word ClassId = 60;
		static const word ClientId = 61;
		static const word NetWare_IPDomain = 62;
		static const word NetWare_IPOption = 63;
		static const word NIS_Domain_Name = 64;
		static const word NIS_Server_Addr = 65;
		static const word Server_Name = 66;
		static const word Bootfile_Name = 67;
		static const word Home_Agent_Addrs = 68;
		static const word SMTP_Server = 69;
		static const word POP3_Server = 70;
		static const word NNTP_Server = 71;
		static const word WWW_Server = 72;
		static const word Finger_Server = 73;
		static const word IRC_Server = 74;
		static const word StreetTalk_Server = 75;
		static const word STDA_Server = 76;
		static const word User_Class = 77;
		static const word DirectoryAgent = 78;
		static const word ServiceScope = 79;
		static const word RapidCommit = 80;
		static const word ClientFQDN = 81;
		static const word RelayAgentInformation = 82;
		static const word iSNS = 83;
		static const word NDSServers = 85;
		static const word NDSTreeName = 86;
		static const word NDSContext = 87;
		static const word BCMCSControllerDomainNamelist = 88;
		static const word BCMCSControllerIPv4addressoption = 89;
		static const word Authentication = 90;
		static const word client_last_transaction_timeoption = 91;
		static const word associated_ipoption = 92;
		static const word ClientSystem = 93;
		static const word ClientNDI = 94;
		static const word LDAP = 95;
		static const word UUID_GUID = 97;
		static const word User_Auth = 98;
		static const word GEOCONF_CIVIC = 99;
		static const word PCode = 100;
		static const word End = 255;

		/* DHCP Messages type */
		static const word DHCPDISCOVER = 1;
		static const word DHCPOFFER = 2;
		static const word DHCPREQUEST = 3;
		static const word DHCPDECLINE = 4;
		static const word DHCPACK = 5;
		static const word DHCPNAK = 6;
		static const word DHCPRELEASE = 7;
		static const word DHCPINFORM = 8;

		/* Type TAGS */
		static const byte BYTE = 0;
		static const byte SHORT = 1;
		static const byte WORD = 2;

		/* Print the options */
		void Print() const;

		/* Get the size of the options (real size, should be used to parse) */
		size_t GetSize() const { return data.GetSize() + 2; };

		/* Get size on options (could be a bad one) */
		size_t GetOptionSize() const {
			if(fake_size) {
				return fake_size + 2;
			}
			return data.GetSize() + 2;
		}

		/* Get the code associated to this option */
		byte GetCode() const { return code; };

		/* Return a payload with all the data */
		Payload GetData() const;

		/* ---- Manipulation of the contents of the data field (could be and IP, string or just raw data) ---- */

		/* Get data as string */
		virtual std::string GetString() const;

		/* Get IP addresses */
		virtual std::vector<std::string> GetIPAddresses() const;

		/* Get a raw pointer to the data */
		byte* GetRawPointer() const;

		/* Get number value of the data */
		virtual word GetNumber() const;

		/* Set Payload from string */
		void SetString(const std::string& str);

		/* Set Payload from IPs */
		void SetIPAdresses(const std::vector<std::string>& ips);

		/* Set Payload from a raw pointer */
		void SetRawPointer(const byte* raw_data, size_t length);

		/* Set a number as DHCP data */
		void SetNumber(word value, byte type);

		/* Set option size */
		void SetOptionSize(size_t sz);

		virtual ~DHCPOptions();
	};

	/* -------- DHCP String */

	class DHCPOptionsString : public DHCPOptions {
		/* String */
		std::string str_data;

		/* Print data */
		void PrintData() const;

		/* Function that set the payload */
		virtual void SetPayload();

		/* Set internal field from the payload of the base class */
		virtual void SetFields();

		/* Get data as string */
		virtual std::string GetString() const {return str_data;};

		DHCPOptions* Clone() const { return new DHCPOptionsString(code,str_data); };
	public:
		DHCPOptionsString(short_word code, const std::string& str_data);

		virtual ~DHCPOptionsString();
	};

	/* -------- DHCP IP */

	class DHCPOptionsIP : public DHCPOptions {
		/* String */
		std::vector<std::string> ip_addresses;

		/* Print data */
		void PrintData() const;

		/* Function that set the payload */
		virtual void SetPayload();

		/* Set internal field from the payload of the base class */
		virtual void SetFields();

		/* Get IP addresses */
		virtual std::vector<std::string> GetIPAddresses() const {return ip_addresses;};

		DHCPOptions* Clone() const { return new DHCPOptionsIP(code,ip_addresses); };

	public:
		DHCPOptionsIP(short_word code, const std::vector<std::string>& ip_addresses);

		virtual ~DHCPOptionsIP();
	};

	/* -------- DHCP Generic */

	class DHCPOptionsGeneric : public DHCPOptions {
		/* String */
		Payload gen_data;

		/* Function that set the payload */
		virtual void SetPayload();

		/* Set internal field from the payload of the base class */
		virtual void SetFields();

		DHCPOptions* Clone() const { return new DHCPOptionsGeneric(code,gen_data.GetContainer()); };

	public:
		DHCPOptionsGeneric(short_word code, const std::vector<byte>& data);

		virtual ~DHCPOptionsGeneric();
	};

	/* -------- DHCP MessageType */

	class DHCPOptionsMessageType : public DHCPOptions {
		/* String */
		byte type;

		/* Print data */
		void PrintData() const;

		/* Function that set the payload */
		virtual void SetPayload();

		/* Function that set the payload */
		virtual void SetFields();

		virtual word GetNumber() const {return type;};

		DHCPOptions* Clone() const { return new DHCPOptionsMessageType(code,type); };

	public:
		DHCPOptionsMessageType(short_word code, byte type);

		virtual ~DHCPOptionsMessageType();
	};

	/* -------- DHCP Parameter List Request */

	class DHCPOptionsParameterList : public DHCPOptions {
		/* String */
		Payload par_data;

		/* Print data */
		void PrintData() const;

		/* Function that set the payload */
		virtual void SetPayload();

		/* Set internal field from the payload of the base class */
		virtual void SetFields();

		DHCPOptions* Clone() const { return new DHCPOptionsParameterList(code,par_data.GetContainer()); };

	public:
		DHCPOptionsParameterList(short_word code, const std::vector<byte>& data);

		virtual ~DHCPOptionsParameterList();
	};

	/* -------- DHCP Number */

	template<class T>
	class DHCPOptionsNumber : public DHCPOptions {
		/* String */
		T value;

		/* Function that set the payload */
		void SetPayload();

		/* Print data */
		void PrintData() const;

		/* Set internal field from the payload of the base class */
		virtual void SetFields();

		virtual word GetNumber() const {return value;};

		DHCPOptions* Clone() const { return new DHCPOptionsNumber<T>(code,value); };

	public:
		DHCPOptionsNumber(short_word code, T value);

		~DHCPOptionsNumber();
	};
}

/* -------- DHCP Number */

static const std::string NumberTag = "Number";

/* Constructor */
template<class T>
Crafter::DHCPOptionsNumber<T>::DHCPOptionsNumber(short_word code, T value) : DHCPOptions(code,NumberTag), value(value) {
	/* Now, set the payload */
	SetPayload();
}

/* Set a payload from a string */
template<class T>
void Crafter::DHCPOptionsNumber<T>::SetPayload() {
	word net_value = 0;
	if (sizeof(T) == sizeof(byte)) {
		net_value = value;
		data.SetPayload((const byte*)&net_value,sizeof(byte));
	}else if (sizeof(T) == sizeof(short_word)) {
		net_value = htons((short_word)value);
		data.SetPayload((const byte*)&net_value,sizeof(short_word));
	}else if (sizeof(T) == sizeof(word)) {
		net_value = htonl((word)value);
		data.SetPayload((const byte*)&net_value,sizeof(word));
	}
}

template<class T>
void Crafter::DHCPOptionsNumber<T>::SetFields() {

	if(data.GetSize() >= sizeof(T)) {
		byte* raw_data = new byte[data.GetSize()];
		data.GetPayload(raw_data);

		if(sizeof(T) == sizeof(byte))
			value = *((T *)(raw_data));
		else if(sizeof(T) == sizeof(short_word))
			value = ntohs(*((T *)(raw_data)));
		else if(sizeof(T) == sizeof(word))
			value = ntohl(*((T *)(raw_data)));

		delete [] raw_data;
	}


}

template<class T>
void Crafter::DHCPOptionsNumber<T>::PrintData() const {
	/* Now, set the payload */
	std::cout <<  value;
}

/* Destructor */
template<class T>
Crafter::DHCPOptionsNumber<T>::~DHCPOptionsNumber() { }

/*  ++++++++++++++ And here is where all the magic occurs... */

namespace Crafter {
	/* This can get the DHCP options data from a string (generic name) */
	DHCPOptions* CreateDHCPOption(short_word code, const std::string& str);

	/* This can get the DHCP options data from a string (IP address) */
	DHCPOptions* CreateDHCPOption(short_word code, const std::vector<std::string>& ip_addresses);

	/* This get the value of the DHCP options data from a word, short or a byte */
	DHCPOptions* CreateDHCPOption(short_word code, word value, byte type_tag);

	/* This put raw_data into the DHCP options data. Ultimately, this is the function to use */
	DHCPOptions* CreateDHCPOption(short_word code, const byte* raw_data, size_t length);
}
#endif /* DHCPOPTIONS_H_ */
