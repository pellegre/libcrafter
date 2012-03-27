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
libcrafter_la_SOURCES = crafter/PrintMessage.cpp \
                        crafter/ARP.cpp \
                        crafter/ARPPing.cpp \
						crafter/ARPSpoofing.cpp \
						crafter/ARPSpoofingReply.cpp \
						crafter/ARPSpoofingRequest.cpp \
						crafter/BitHandling.cpp \
						crafter/CrafterUtils.cpp \
						crafter/DNS.cpp \
						crafter/DNSAnswer.cpp \
						crafter/DNSQuery.cpp \
						crafter/Ethernet.cpp \
						crafter/Field.cpp \
						crafter/ICMP.cpp \
						crafter/IP.cpp \
						crafter/IPResolver.cpp \
						crafter/IPSeudoHeader.cpp \
						crafter/IPv4Parse.cpp \
						crafter/Layer.cpp \
						crafter/Packet.cpp \
						crafter/Payload.cpp \
						crafter/RawLayer.cpp \
						crafter/RawSocket.cpp \
						crafter/Sniffer.cpp \
						crafter/TCPConnection.cpp \
						crafter/TCP.cpp \
						crafter/UDP.cpp 

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
                                crafter/ARP.h \
                                crafter/ARPPing.h \
								crafter/ARPSpoofing.h \
								crafter/Crafter.h \
								crafter/CrafterUtils.h \
								crafter/BitHandling.h \
								crafter/DNS.h \
								crafter/Ethernet.h \
								crafter/Field.h \
								crafter/ICMP.h \
								crafter/IP.h \
								crafter/IPResolver.h \
								crafter/IPSeudoHeader.h \
								crafter/IPv4Parse.h \
								crafter/Layer.h \
								crafter/Packet.h \
								crafter/Payload.h \
								crafter/PrintMessage.h \
								crafter/RawLayer.h \
								crafter/RawSocket.h \
								crafter/Sniffer.h \
								crafter/TCPConnection.h \
								crafter/TCP.h \
								crafter/UDP.h

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
pkgconfig_DATA = crafter-$(CRAFTER_API_VERSION).pc

## Put additional flags, including libpcap and libnet linking information
AM_CPPFLAGS = $(PCAPINC) $(LNETINC)
AM_CXXFLAGS = -ansi -pedantic -Wall

## Define an independent executable script for inclusion in the distribution
## archive.  However, it will not be installed on an end user's system due to
## the noinst_ prefix.
dist_noinst_SCRIPTS = autogen.sh
