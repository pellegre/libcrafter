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
libcrafter_la_SOURCES = crafter/Utils/PrintMessage.cpp \
                        crafter/Protocols/ARP.cpp \
                        crafter/Utils/ARPPing.cpp \
						crafter/Utils/ARPSpoofing.cpp \
						crafter/Utils/ARPSpoofingReply.cpp \
						crafter/Utils/ARPSpoofingRequest.cpp \
						crafter/Utils/BitHandling.cpp \
						crafter/Utils/CrafterUtils.cpp \
						crafter/Protocols/DHCP.cpp \
						crafter/Protocols/DHCPOptions.cpp \
						crafter/Protocols/DNS.cpp \
						crafter/Protocols/DNSAnswer.cpp \
						crafter/Protocols/DNSQuery.cpp \
						crafter/Protocols/Ethernet.cpp \
						crafter/Field.cpp \
						crafter/Protocols/ICMP.cpp \
						crafter/Protocols/ICMPExtension.cpp \
						crafter/Protocols/ICMPExtensionMPLS.cpp \
						crafter/Protocols/ICMPExtensionObject.cpp \
						crafter/Protocols/IP.cpp \
						crafter/Utils/IPResolver.cpp \
						crafter/Protocols/IPSeudoHeader.cpp \
						crafter/Utils/IPv4Parse.cpp \
						crafter/Layer.cpp \
						crafter/Packet.cpp \
						crafter/Payload.cpp \
						crafter/Protocols/RawLayer.cpp \
						crafter/Utils/RawSocket.cpp \
						crafter/Utils/Sniffer.cpp \
						crafter/Utils/TCPConnection.cpp \
						crafter/Protocols/TCP.cpp \
						crafter/Protocols/UDP.cpp 

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
                                crafter/Protocols/ARP.h \
                                crafter/Utils/ARPPing.h \
								crafter/Utils/ARPSpoofing.h \
								crafter/Crafter.h \
								crafter/Utils/CrafterUtils.h \
								crafter/Utils/BitHandling.h \
								crafter/Protocols/DHCP.h \
								crafter/Protocols/DHCPOptions.h \
								crafter/Protocols/DNS.h \
								crafter/Protocols/Ethernet.h \
								crafter/Field.h \
								crafter/Protocols/ICMP.h \
								crafter/Protocols/ICMPExtension.h \
								crafter/Protocols/ICMPExtensionMPLS.h \
								crafter/Protocols/ICMPExtensionObject.h \
								crafter/Protocols/IP.h \
								crafter/Utils/IPResolver.h \
								crafter/Protocols/IPSeudoHeader.h \
								crafter/Utils/IPv4Parse.h \
								crafter/Layer.h \
								crafter/Packet.h \
								crafter/Payload.h \
								crafter/Utils/PrintMessage.h \
								crafter/Protocols/RawLayer.h \
								crafter/Utils/RawSocket.h \
								crafter/Utils/Sniffer.h \
								crafter/Utils/TCPConnection.h \
								crafter/Protocols/TCP.h \
								crafter/Protocols/UDP.h

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

## Put additional flags, including libpcap and libnet linking information
AM_CPPFLAGS = $(PCAPINC) $(LNETINC)
AM_CXXFLAGS = -ansi -pedantic -Wall

## Define an independent executable script for inclusion in the distribution
## archive.  However, it will not be installed on an end user's system due to
## the noinst_ prefix.
dist_noinst_SCRIPTS = autogen.sh
