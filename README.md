Resilient IP Protocol (ResIP) PHP Prototype
===========================================

The very first prototype implementation of the Resilient Internet Protocol (ResIP).  ResIP is a modern tunneling protocol designed to withstand a wide range of network conditions and has features beyond what TCP/IP can offer.  This prototype is written in PHP.  MIT or LGPL, your choice.

[![Donate](https://cubiclesoft.com/res/donate-shield.png)](https://cubiclesoft.com/donate/)

Protocol Features
-----------------

* A reimagined TCP/IP:  Client-driven connectivity instead of server-driven.
* Connections can survive complete outages exceeding 72 hours.
* Connections survive IP address changes.
* Designed to deal with high packet loss and high latency scenarios.
* Multiplexed channels.
* Reverse multihoming.  A single client can bounce freely between several IP addresses (e.g. a user on a train with a mobile device).
* Quadruple encrypted packetized binary data structure between ResIP client and server.  Global and per-session encryption and digitally signed packets.
* Transparent compression and packet fragmentation support.

This Is A Prototype
-------------------

The software, as-is, is extremely prototype-ey and, in its current state, should be viewed as simply a demo of the protocol.  It took just shy of two months to get what you see here into a functional state.  This PHP based prototype works but don't expect anything spectacular.  It is, after all, a set of servers and clients written in PHP.  PHP is a fantastic language to prototype something like this in - it allows me to significantly shorten the dev-test cycle.

Demo Installation
-----------------

Pull down this repository as one does.  Fire up four Command Prompts/terminal sessions.  Go into the 'client' and 'server' directories and run:

````php install.php````

When you get to the "whitelist" section of the ResIP server installer, be sure to add '127.0.0.1' otherwise it won't work.

Follow this order of instructions to run the demo:

* Window 1:  'test' directory.  Execute 'php server.php'.  This opens localhost port 10000.
* Window 2:  'server' directory.  Execute 'php server.php'.
* Window 3:  'client' directory.  Execute 'php client.php tcp localhost 10000 N N 4000 N'.  This listens on localhost port 4000 and routes incoming connections through the ResIP server (Window 2) to localhost port 10000 (Window 1).
* Window 4:  'test' directory.  Execute 'php client.php'.  This connects to port 4000 on localhost (Window 3).

If all goes well, the following output will be in Window 4:

````
Sending:  LOGIN
Received:  Logged in.  Fantastic.
Sending:  DATA
Received:  Sending data.
Sending:  QUIT
Received:  Quitting.
````

If you want to deploy this for real, you will need a host you deem "reliable" to install the server onto.  Most cloud-based hosts offer some pretty nice options as a decent intermediate.  Alternatively, a specific server if you want it behind a corporate firewall or some such.  You might want to read the How It Works section below if you need more refined on-host results.

How It Works
------------

The Resilient IP server and client are a pair.  The actual specification for ResIP itself doesn't declare how sessions are established.  This demo just demonstrates one possible way that can happen - in this case, using an API key over HTTPS to get a session ID and a set of encryption and signing keys.  Once the session is established, the client and the server can start talking to each other.  Packet communication is preferably performed over UDP/IP but there is a fallback option to use TCP/IP (e.g. firewall rules might prevent UDP from functioning).  Every packet over ResIP is encrypted using [CubicleSoft dual encryption](http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html) with a forced packet size of 512 bytes for a number of different reasons.  There is approximately 10% overhead with ResIP when the full packet space is used, which will generally be the majority of data packets sent and received.  However, packet space can be wasted in excess of 80% for certain packet types (e.g. mostly empty ACK packets).  Some testing needs to be done here to determine how much and how frequently space is wasted.

A key concept of ResIP is that the client drives the server and, to do that, data is multiplexed across "channels".  Channel 0 is the command channel.  It is used to establish and manage the other channels as well as perform some other minor functionality (e.g. keep-alive verification heartbeat packets).  A channel is a single IP packet stream.  For TCP connections, which accounts for most traffic on the Internet, data coming in is chunked into UDP packet sizes (unfragmented UDP is 512 bytes) and reassembled on the other side before sending them on to the destination.  From an application's perspective, all the work being done to slice up packet data is transparent.  ACKnowledgement packets (ACK packets) arrive on the command channel with a packet number of 0 and can acknowledge receipt of multiple packets for multiple channels.  Due to how the aforementioned encryption portion of the protocol was designed, the protocol attempts to save up and group as many ACK packets as possible to minimize bandwidth usage.  This server and client implementation of the protocol allow all packets to arrive out of order and will be reassembled in order.  The only exception to this rule are ACK and keep-alive packets, which are sent as unordered packet data (packet 0 on the command channel).

To survive IP address changes, the server side of ResIP keeps track of clients on a floating time basis.  Valid packets that arrive from a client for an existing session and channel get routed response packets back to that client.  This, of course, could lead to MITM style attacks but only the server and client have the encryption keys.  The prototype here is just a demo of the protocol, maybe for internal use on a limited basis such as deployment to trusted individuals who are experiencing network issues.  This separation capability of the ResIP server/client infrastructure, however, allows the protocol and implementation here to do some pretty wild stuff such as allow the ResIP client to go offline for extremely long periods of time without receiving a single packet on the server end of things.  If both ResIP server and client are talking to application endpoints on their 'localhost', the end result is an infinite TCP/IP connection guaranteed to eventually deliver all data to the target application.  As long as the application doesn't timeout the connection nor the ResIP server or client restarts, the OS will never terminate the connection, which allows ResIP to do its thing.  One such usage could be a tunnel to a SSH server on a remote host, which could allow continuous but slow access to a server undergoing a DDoS attack.

Background And Use Cases
------------------------

Over the years, I have observed that networks have the tendency to be flaky or broken.  Network reliability is actually somewhere between flaky and broken.  My first real encounter which inspired this project was shortly after a severe lightning storm where I noticed a severe drop in network performance when sending data to the outbound Internet through a major ISP.  After digging around for a while, I discovered that I was encountering 30% packet loss.  I did the usual things that ISPs typically recommend but nothing helped and, in fact, over the course of a month, packet loss grew even worse.  By the end, I was experiencing 99% packet loss, ~300 bytes/sec transfer rates, nearly every TCP/IP connection dropped, the ISP was at a total loss and they wanted to charge me some absurd amount of money to violate building codes to possibly fix THEIR problem (they were simply guessing at that point), I was very frustrated, and the issue was no closer to being resolved.  I ended up finding and switching to another ISP and haven't had a single problem since.

However, after that, I started noticing the little things with networking equipment that most people just ignore.  Downtime, extreme packet loss, IP address changes causing connection breakages, scripts sending automated e-mail notifications that something with the network has gone wrong (again), [this guy in Sri Lanka](http://tortoisesvn.tigris.org/ds/viewMessage.do?dsForumId=757&dsMessageId=2701790) trying to transfer large-ish amounts of data to/from Subversion hosted in Canada, mobile devices such as smartphones in transit (e.g. on a train), problems with data transfers over high latency networks (e.g. satellite ISPs), network reliability in third world countries, server communication problems with certain network enabled attacks (e.g. DDoS), and the list goes on.  TCP/IP is great and can deal with a large number of problems but sometimes we just need reliability of packet delivery to very specific hosts.  Whenever anyone has ever needed that, there weren't, before ResIP, any options and so they just had to put up with the issues.

This protocol went through a few major and a couple of minor revisions on paper before a single line of code was written.  As people who know me would attest to under oath, I don't put much onto paper, so this was clearly a very significant undertaking when I ended up using two whole sheets of paper.

Packet Structure
----------------

These next two sections cover details of how the packets are formed.  These sections are highly technical and you should have a solid understanding of how binary protocols work.

Integers are, generally speaking, packed.  Integers are stored in big-endian format.  There is usually a starting byte that has a few bits to indicate the number of bytes of various integers that follow minus 1.  This behavior allows two bits to declare a 4 byte (32-bit) integer.

Packets are structured with an outer data wrapper and an interor data wrapper.

The interior data wrapper looks like:

* 1 byte - Random data.
* 1 byte - 1 bit source client (0) or server (1), 1 bit compressed, 1 bit message continued (fragmented data), 2 bits channel size, 3 bits packet number size.
* 1-4 bytes - Channel number.
* 1-8 bytes - Packet number.
* 2 bytes - Packet data size.
* x bytes - Packet data.
* n bytes - Random data where 'n' is 'Packet size - 32 - length of data above'.  This also pads the packet out to a multiple of the encryption block size.

The interior data wrapper is encrypted using the session keys.  To allow the server to know which session is in use (so it can correctly decrypt incoming packets), the packet is encased inside an outer data wrapper.

The outer data wrapper looks like:

* 1 byte - Random data.
* 1 byte - 4 bits reserved, 4 bits packet type (0).
* 4 bytes - Session ID.
* x bytes - Interior data from above.  Generally this will be 'Packet size - 32' bytes.
* n bytes - Random data where 'n' is '32 - hash length - 6'.
* y bytes - Binary representation of a HMAC for a digital signature.  The hash is chosen during session setup and defaults to SHA-1.

Command Channel Structures
--------------------------

The command channel is channel 0.  Packets on the command channel must not be compressed or fragmented.  The first byte of a data packet for the command channel is as follows:

* 1 byte - 3 bits reserved, 5 bits command.

Commands are accepted by both the ResIP server and client.  However, certain commands are expected to have different actions for the same command.  To aid in understanding packet structure and purpose, commands are broken down by client to server and vice versa.

Client to server - Command 1 (x01) - Start Channel - Request a socket to be opened to the specified target host:

* 1 byte - 1 bit compression support, 1 bit fragmentation support (1), 2 bits channel size, 2 bits IP version (0 = IPv4, 1 = IPv6), 2 bits port number size.
* 1-4 bytes - Channel number.
* 1 byte - Protocol number.  TCP is 6 (0x06), UDP is 17 (0x11), ICMP is 1 (0x01).
* 4 or 16 bytes - IP address.  IPv4 is 4 bytes.  IPv6 is 16 bytes.
* 1-2 bytes - Port number.  Technically, more port numbers are supported, but no underlying transport supports them at this time.

Server to client - Command 1 (x01) - Channel started, socket opened - Confirms that the socket was opened (Stop channel is used on failure):

* 1 byte - 6 bits reserved, 2 bits channel size.
* 1-4 bytes - Channel number.

Both - Command 2 (x02) - Stop channel - Lets the other side know that the end of the data stream is in progress (Does not terminate the channel!):

* 1 byte - 3 bits reserved, 2 bits channel size, 3 bits last packet size.
* 1-4 bytes - Channel number.
* 1-8 bytes - Last packet number.

Both - Command 3 (x03) - ACK - Acknowledges receipt of one or more single packets and/or ranges of packets:

* 1 byte - 1 bit (0), 5 bits reserved, 2 bits channel size.
* 1-4 bytes - Channel number.

Followed by one or more of:

* 1 byte - 1 bit (1), 1 bit range, 3 bits packet number size, 3 bits packet number size (unused when 'range' is 0).
* 1-8 bytes - Starting packet number received.
* 0-8 bytes - Ending packet number received for this range.

The first bit of a byte section indicates whether it is part of the range of ACKs for the channel or a different channel.  Since ACKs are only sent every half-second at most, this allows time to accumulate quite a few ACKs and thus likely create a fairly compact set of ACK packets.  The exception is connection teardown where, in order to speed things up, an ACK may be triggered early.

Client to server - Command 4 (x04) - Keep-alive check - Verify that the ResIP server is still there.  There is no data for this command.  Clients initiate this packet usually after a long time of not receiving anything so that they are ready if another command or packet becomes ready to send.

Server to client - Command 4 (x04) - Keep-alive response - Assigns the ResIP client to the correct session if the association was lost and responds with keep-alive.  There is no data for this command.  Clients are expected to do nothing other than realize that the server is still there and all is well.

Client to server - Command 5 (x05) - Terminate channel - Tells the server to immediately terminate the channel.  There is no server response to this packet:

* 1 byte - 6 bits reserved, 2 bits channel size.
* 1-4 bytes - Channel number.
