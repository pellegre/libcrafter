# libcrafter

A high-level C++ library for crafting, decoding, and manipulating network packets.

## Overview

**libcrafter** is a network packet manipulation library for C++ that provides an intuitive, Scapy-like interface for creating and analyzing network traffic. It enables developers to build powerful networking tools with minimal code by representing packets as stackable protocol layers with sensible defaults.

The library is designed with multithreading in mind, allowing you to simultaneously sniff, modify, and transmit packets, ideal for network security tools, traffic analysis, and protocol testing.

## Features

- **Packet Crafting**: Build custom network packets by stacking protocol layers
- **Packet Decoding**: Parse raw network data into structured protocol objects
- **Send & Receive**: Transmit packets and capture responses with automatic request/reply matching
- **Sniffing**: Capture live traffic with BPF filter support
- **Concurrent**: Designed for concurrent operations in multithreaded applications

## Supported Protocols

| Layer 2 | Layer 3 | Layer 4 | Application |
|---------|---------|---------|-------------|
| Ethernet | IPv4 | TCP | DNS |
| 802.1Q (VLAN) | IPv6 | UDP | DHCP |
| SLL (Linux cooked) | ICMP | TCP Options | |
| Null/Loopback | ICMPv6 | | |
| | IP Options | | |
| | IPv6 Extensions | | |
| | ICMP Extensions | | |

### IPv6 Extension Headers
- Fragmentation Header
- Routing Header
- Segment Routing Header
- Mobile Routing Header

### TCP Options
- Maximum Segment Size
- Timestamps
- Window Scale
- MPTCP
- Padding (NOP, EOL)

### IP Options
- Traceroute
- Loose/Strict Source Routing (Pointer-based)
- Padding

## Project Structure

```
libcrafter/
├── crafter/
│   ├── Crafter.h          # Main header including all protocols
│   ├── Layer.h/cpp        # Base class for all protocol layers
│   ├── Packet.h/cpp       # Packet container and manipulation
│   ├── Payload.h/cpp      # Raw payload handling
│   ├── Fields/            # Field types (IP addresses, MAC, numerics, etc.)
│   ├── Protocols/         # Protocol implementations (Ethernet, IP, TCP, etc.)
│   ├── Utils/             # Utilities (Sniffer, ARP tools, helpers)
│   └── ProtoSource/       # Protocol definition source files
├── crafter.h              # Public include header
├── configure.ac           # Autoconf configuration
├── Makefile.am            # Automake build rules
└── autogen.sh             # Bootstrap script
```

## Dependencies

- **libpcap** - Packet capture library
- **pthread** - POSIX threads
- **libresolv** - DNS resolver (for DNS protocol support)
- **autoconf** & **libtool** - Build system (for compilation from source)

### Installing Dependencies

**Debian/Ubuntu:**
```bash
sudo apt-get install libpcap libpcap-dev autoconf libtool
```

**Fedora/RHEL:**
```bash
sudo dnf install libpcap libpcap-devel autoconf libtool
```

**macOS (Homebrew):**
```bash
brew install libpcap autoconf libtool
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/pellegre/libcrafter
cd libcrafter/libcrafter

# Generate build system and compile
./autogen.sh
make

# Install system-wide (requires root)
sudo make install
sudo ldconfig
```

### Build Options

You can specify a custom libpcap location:
```bash
./configure --with-libpcap=/path/to/libpcap
```

## Quick Start

### Include the Library

```cpp
#include <crafter.h>
using namespace Crafter;
```

### Initialize/Cleanup

```cpp
int main() {
    InitCrafter();
    
    // Your code here
    
    CleanCrafter();
    return 0;
}
```

### Craft a TCP SYN Packet

```cpp
// Create layers
Ethernet ether;
ether.SetSourceMAC("aa:bb:cc:dd:ee:ff");
ether.SetDestinationMAC("11:22:33:44:55:66");

IP ip;
ip.SetSourceIP("192.168.1.100");
ip.SetDestinationIP("192.168.1.1");

TCP tcp;
tcp.SetSrcPort(12345);
tcp.SetDstPort(80);
tcp.SetFlags(TCP::SYN);

// Stack layers into a packet
Packet packet = ether / ip / tcp;

// Send the packet
packet.Send("eth0");
```

### Sniff Packets

```cpp
void PacketHandler(Packet* packet, void* user) {
    packet->Print();
}

Sniffer sniff("tcp port 80", "eth0", PacketHandler);
sniff.Capture(10);  // Capture 10 packets
```

### Decode Raw Data

```cpp
byte raw_data[] = { /* raw packet bytes */ };
Packet packet;
packet.PacketFromEthernet(raw_data, sizeof(raw_data));
packet.Print();
```

## Compilation

Link against libcrafter when compiling your programs:

```bash
g++ -o prog prog.cpp -lcrafter -lpcap -lpthread
```

Or use pkg-config:
```bash
g++ -o prog prog.cpp $(pkg-config --cflags --libs crafter)
```

## Examples

More examples are available at:
https://github.com/pellegre/libcrafter-examples

## License

This project is licensed under the **BSD 3-Clause License**. See the [LICENSE](libcrafter/LICENSE) file for details.

## Author

**Esteban Pellegrino**

