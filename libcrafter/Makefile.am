## LibCrafter (Adapted from http://www.openismus.com/documents/linux/building_libraries/building_libraries):

## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

## Additional flags to pass to aclocal when it is invoked automatically at
## make time. The ${ACLOCAL_FLAGS} variable is picked up from the environment
## to provide a way for the user to supply additional arguments.
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

## Define a libtool archive target "libcrafter.la".
## The libtool archive file (.la) will be installed into the directory named
## by the predefined variable $(bindir), along with the actual shared library
## file (.so).
lib_LTLIBRARIES = libcrafter.la

## Define the source file list for the "libcrafter.la" target.  
## The file extension .cpp is recognized by Automake, and makes it produce
## rules which invoke the C++ compiler to produce a libtool object file (.lo)
## from each source file.  Note that it is not necessary to list header files
## which are already listed elsewhere in a _HEADERS variable assignment.
libcrafter_la_SOURCES = crafter/Layer.cpp \
						crafter/Payload.cpp \
						crafter/Packet.cpp \
						crafter/PacketDecoder.cpp \
						crafter/Utils/PrintMessage.cpp \
						crafter/Utils/BitHandling.cpp \
						crafter/Utils/IPResolver.cpp \
						crafter/Utils/IPv4Parse.cpp \
						crafter/Utils/RawSocket.cpp \
						crafter/Utils/CrafterUtils.cpp \
						crafter/Utils/PacketContainer.cpp \
						crafter/Utils/ARPPing.cpp \
						crafter/Utils/ARPSpoofing.cpp \
						crafter/Utils/ARPSpoofingReply.cpp \
						crafter/Utils/ARPSpoofingRequest.cpp \
						crafter/Utils/Sniffer.cpp \
						crafter/Utils/TCPConnection.cpp \
						crafter/Fields/FieldContainer.cpp \
						crafter/Fields/FieldInfo.cpp \
						crafter/Fields/IPAddress.cpp \
						crafter/Fields/IPv6Address.cpp \
						crafter/Fields/MACAddress.cpp \
						crafter/Fields/NumericFields.cpp \
						crafter/Protocols/RawLayer.cpp \
						crafter/Protocols/EthernetConstructor.cpp \
						crafter/Protocols/EthernetCraft.cpp \
						crafter/Protocols/ARPConstructor.cpp \
						crafter/Protocols/ARPCraft.cpp \
						crafter/Protocols/IPConstructor.cpp \
						crafter/Protocols/IPCraft.cpp \
						crafter/Protocols/IPOptionConstructor.cpp \
						crafter/Protocols/IPOptionCraft.cpp \
						crafter/Protocols/IPOptionPadConstructor.cpp \
						crafter/Protocols/IPOptionPadCraft.cpp \
						crafter/Protocols/IPOptionTracerouteConstructor.cpp \
						crafter/Protocols/IPOptionTracerouteCraft.cpp \
						crafter/Protocols/IPOptionPointerConstructor.cpp \
						crafter/Protocols/IPOptionPointerCraft.cpp \
						crafter/Protocols/UDPConstructor.cpp \
						crafter/Protocols/UDPCraft.cpp \
						crafter/Protocols/TCPConstructor.cpp \
						crafter/Protocols/TCPCraft.cpp \
						crafter/Protocols/TCPOptionConstructor.cpp \
						crafter/Protocols/TCPOptionCraft.cpp \
						crafter/Protocols/TCPOptionPadConstructor.cpp \
						crafter/Protocols/TCPOptionPadCraft.cpp \
						crafter/Protocols/TCPOptionMaxSegSizeConstructor.cpp \
						crafter/Protocols/TCPOptionMaxSegSizeCraft.cpp \
						crafter/Protocols/TCPOptionTimestampConstructor.cpp \
						crafter/Protocols/TCPOptionTimestampCraft.cpp \
						crafter/Protocols/ICMPConstructor.cpp \
						crafter/Protocols/ICMPCraft.cpp \
						crafter/Protocols/ICMPExtensionConstructor.cpp \
						crafter/Protocols/ICMPExtensionCraft.cpp \
						crafter/Protocols/ICMPExtensionMPLSConstructor.cpp \
						crafter/Protocols/ICMPExtensionMPLSCraft.cpp \
						crafter/Protocols/ICMPExtensionObjectConstructor.cpp \
						crafter/Protocols/ICMPExtensionObjectCraft.cpp \
						crafter/Protocols/DNSConstructor.cpp \
						crafter/Protocols/DNSCraft.cpp \
						crafter/Protocols/DNSQuery.cpp \
						crafter/Protocols/DNSAnswer.cpp \
						crafter/Protocols/DHCPConstructor.cpp \
						crafter/Protocols/DHCPCraft.cpp \
						crafter/Protocols/DHCPOptions.cpp \
						crafter/Protocols/SLLConstructor.cpp \
						crafter/Protocols/SLLCraft.cpp \
						crafter/Protocols/IPv6Constructor.cpp \
						crafter/Protocols/IPv6Craft.cpp

## Instruct libtool to include ABI version information in the generated shared
## library file (.so).  The library ABI version is defined in configure.ac, so
## that all version information is kept in one place.
libcrafter_la_LDFLAGS = -version-info $(CRAFTER_SO_VERSION)
libcrafter_la_LIBADD = $(PCAPLIB) $(LNETLIB)

## Define the list of public header files and their install location.  The
## nobase_ prefix instructs Automake to not strip the directory part from each
## filename, in order to avoid the need to define separate file lists for each
## installation directory.  This only works if the directory hierarchy in the
## source tree matches the hierarchy at the install location, however.
crafter_includedir = $(includedir)
nobase_crafter_include_HEADERS =crafter.h \
								crafter/Crafter.h \
								crafter/Layer.h \
								crafter/Payload.h \
								crafter/Packet.h \
								crafter/Types.h \
								crafter/Fields/BitsField.h \
								crafter/Fields/BytesField.h \
								crafter/Fields/FieldContainer.h \
								crafter/Fields/Field.h \
								crafter/Fields/FieldInfo.h \
								crafter/Fields/IPAddress.h \
								crafter/Fields/IPv6Address.h \
								crafter/Fields/MACAddress.h \
								crafter/Fields/NumericFields.h \
								crafter/Fields/StringField.h \
								crafter/Utils/BitHandling.h \
								crafter/Utils/IPResolver.h \
								crafter/Utils/IPv4Parse.h \
								crafter/Utils/PrintMessage.h \
								crafter/Utils/RawSocket.h \
								crafter/Utils/CrafterUtils.h \
								crafter/Utils/PacketContainer.h \
								crafter/Utils/ARPPing.h \
								crafter/Utils/ARPSpoofing.h \
								crafter/Utils/Sniffer.h \
								crafter/Utils/TCPConnection.h \
								crafter/Protocols/RawLayer.h \
								crafter/Protocols/Ethernet.h \
								crafter/Protocols/ARP.h \
								crafter/Protocols/IP.h \
								crafter/Protocols/IPOption.h \
								crafter/Protocols/IPOptionLayer.h \
								crafter/Protocols/IPOptionPad.h \
								crafter/Protocols/IPOptionTraceroute.h \
								crafter/Protocols/IPOptionPointer.h \
								crafter/Protocols/UDP.h \
								crafter/Protocols/TCP.h \
								crafter/Protocols/TCPOption.h \
								crafter/Protocols/TCPOptionLayer.h \
								crafter/Protocols/TCPOptionPad.h \
								crafter/Protocols/TCPOptionMaxSegSize.h \
								crafter/Protocols/TCPOptionTimestamp.h \
								crafter/Protocols/ICMP.h \
								crafter/Protocols/ICMPExtension.h \
								crafter/Protocols/ICMPExtensionMPLS.h \
								crafter/Protocols/ICMPExtensionObject.h \
								crafter/Protocols/DNS.h \
								crafter/Protocols/DHCP.h \
								crafter/Protocols/DHCPOptions.h \
								crafter/Protocols/SLL.h \
								crafter/Protocols/IPv6.h \
								crafter/Protocols/IPLayer.h

## The generated configuration header is installed in its own subdirectory of
## $(libdir).  The reason for this is that the configuration information put
## into this header file describes the target platform the installed library
## has been built for.  Thus the file must not be installed into a location
## intended for architecture-independent files, as defined by the Filesystem
## Hierarchy Standard (FHS).
## The nodist_ prefix instructs Automake to not generate rules for including
## the listed files in the distribution on 'make dist'.  Files that are listed
## in _HEADERS variables are normally included in the distribution, but the
## configuration header file is generated at configure time and should not be
## shipped with the source tarball.
crafter_libincludedir = $(libdir)/crafter-$(CRAFTER_API_VERSION)/include
nodist_crafter_libinclude_HEADERS = crafterconfig.h

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information.  Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = crafter.pc

## Put additional flags, including libpcap linking information
AM_CPPFLAGS = $(PCAPINC) 
AM_CXXFLAGS = -ansi -pedantic -Wall 

## Define an independent executable script for inclusion in the distribution
## archive.  However, it will not be installed on an end user's system due to
## the noinst_ prefix.
dist_noinst_SCRIPTS = autogen.sh
