# Introduction

Libcrafter is a high level library for C++ designed to create and decode network 
packets. It is able to craft or decode packets of most common networks protocols, 
send them on the wire, capture them and match requests and replies.

It enables the creation of networking tools in a few lines with a interface 
very similar to Scapy. 

A packet is  described as layers that you stack one upon the other. Fields of 
each layer have useful default values that you can overload.

The library is designed to be used in multithreaded programs where you can 
combine several tasks simultaneously. For example, you can easily design 
something that sniffs, mangles, and sends at the same time you are doing 
an ARP-Spoofing attack.

It also contains a very naive implementation of the TCP/IP stack (fragmentation 
is no handled yet) at user level that enables working with TCP streams. This 
facilitates the creation of tools for data injection on arbitrary connections, 
IP spoofing and TCP/IP session hijacking. 

# License 

libcrafter is licensed under the terms of the new BSD license (see LICENSE file 
for more details)
