# DD2391-Project-Group7

## Problem Statement

Networks face various types of attacks including DDoS attacks, such as ACK floods or SYN floods. Filtering and blocking these types of attack is crucial when building a firewall (for example, with TCP state tables and SYN cookies). This project implements a custom firewall, to demonstrate packet interception, parsing it, and filtering for attacks such as SYN floods. The project also includes an attack simulator inside a Docker network to demonstrate and test the firewall. Additionally, the project also consists of a web server in order to verify attack and defense mechanisms.

## Technical Description

The project consist of a server (web server, i.e. the target), a client (the SYN flood attack simulator) and as well as a firewall (intercepts and processes all packets between the client and the server).

The entire project runs inside Docker network where each component has a specific IP addresses within 172.28.x.x. The firewall that we have created should accept or decline packets. From the client, we should be able to ping the server on IP `ping 172.28.2.20`.

### Client

The client runs inside a Docker container. It is a Go executable that is meant to simulate a SYN flood attack to specific IP and port. You can access the client container by running `docker compose exec -it client ash` which will open a shell inside the client. Here you will find a binary called `./client` that you can use to trigger the attack. It has a few command line flags that can be specified (see `-h` for help).

- `duration`: number of seconds to run the SYN flood
- `port`: the target port, by default this is `80` since that is what the web server is listening on
- `src`: source IP address, by default this is `172.28.1.10` which is the IP of the client container inside the Docker Network
- `target`: target IP address, by default this is `172.28.2.20` which is the IP of the server container inside the Docker Network
- `threads`: number of concurrent threads to run the attack with

Technically, this is implemented in Go and works by using raw sockets to send malicious packets. It has three modes:

- Standard: Sends high volume SYN floods with random source ports. It ignores the SYN ACK we get from the server, exhausting connection queues.
- Malformed Offset: Sends packets with malformed TCP header offset field.
- Malformed Opt: Sends invalid TCP option lengths.

### Server

The server runs inside a Docker container running a http server with `python3 -m http.server 80`. The server is located on `172.28.2.20` and can be reached with `curl http://172.28.2.20`.

A simple version of SYN cookies are partially implemented. In a complete implementation of SYN cookies, the server hashes the source ip and port, along with the destination ip and port. A secret key that is generated and refreshed every hour is also part of the hash. The hash is sent as the sequence number in the SYN+ACK response. No data from the SYN request is saved. When an ACK is received, the server recomputes the hash according to the source and destination, if the received cookie matches the computed hash a connection is opened. Since the cookies are not implemented in the web server, there is a test file to test the implementation of the cookies instead. The full implementation is not done since a member of the group dropped out.

### Firewall

The firewall contains a TCP state table. A TCP state table is a small in-memory database that tracks TCP flows. The table contains an entry for each TCP flow, where it tracks the state of the connection aswell as a Flow Key (srcIP, dstIP, scrPort, dstPort), Origin, and Timestamp. This allows the firewall to decide which packets belong to legitimate connections and which should be dropped.

The TCP state table has a global limit for how many half-open (SYN_SENT + SYN_RECV) connections request are allowed (globalHalfOpenLimit). After this limit is reached, all new SYN requests are dropped. This protects against a multiple IP SYN flood (by suspending all new connections).

The TCP state table also has a by-IP limit for how many half-open connections requests are allowed. After this limit is reached, the IP address is blocked from making new SYN request for a set time. This protects agains a single IP SYN flood (by blocking the potentially malicious IP, while still allowing other IP-addresses to make new connections).

The firewall contains a TCP state table monitor which allows us to see the contents of the TCP state table in two minute intervalls, aswell as banned IP addresses.

The firewall also contains a TCP validity check. This check filters out invalid TCP flag combonations which should never appear in a legitimate TCP packet. The check also filters out packets with invalid TCP header lengths.

### How to use

To run this project, you need to have Docker installed. You can install it [here](https://docs.docker.com/engine/install/), or you can install Docker Desktop.

Once you have cloned the repository to your computer, use `docker compose` to start the containers.

```bash
docker compose up --build
```

The `--build` flag makes sure all Docker images are built before running them.

Once running, the log output from all three containers (`firewall`, `client` and `server` will be logged in your console).

You can now open another terminal to attach this terminal to a shell of the client image.

```bash
docker compose exec -it client ash
```

You know have a shell inside the `client` container. If you try to ping and curl the server from here, you should see your packets being processed by the firewall in the first terminal.

```
/app # ping 172.28.2.20
PING 172.28.2.20 (172.28.2.20): 56 data bytes
64 bytes from 172.28.2.20: seq=0 ttl=63 time=0.700 ms
64 bytes from 172.28.2.20: seq=1 ttl=63 time=1.179 ms
64 bytes from 172.28.2.20: seq=2 ttl=63 time=1.265 ms
64 bytes from 172.28.2.20: seq=3 ttl=63 time=0.927 ms
64 bytes from 172.28.2.20: seq=4 ttl=63 time=0.955 ms
^C
--- 172.28.2.20 ping statistics ---
5 packets transmitted, 5 packets received, 0% packet loss
round-trip min/avg/max = 0.700/1.005/1.265 ms
/app # curl 172.28.2.20
<html><body>
<h1>Vulnerable Test Server</h1>
<p>If you can see this, the server is responding.</p>
</body></html>
```

You can run the SYN flood by running `./client`.

```
/app # ./client -threads 10
Starting SYN flood attack:
  Target: 172.28.2.20:80
  Threads: 10
  Duration: 10s
Thread 1: Sent 1269366 packets
Thread 9: Sent 1257863 packets
Thread 7: Sent 1287176 packets
Thread 0: Sent 1284762 packets
Thread 3: Sent 1258745 packets
Thread 4: Sent 1273418 packets
Thread 8: Sent 1273369 packets
Thread 6: Sent 1285131 packets
Thread 5: Sent 1263395 packets
Thread 2: Sent 1279911 packets

Attack completed
```

In the firewall, you can see when running curl on the client that the firewall logs:

```
firewall-1  | 2025/10/19 15:18:40 http: serving state table on :8080 (/, /dump)
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.1.10 -> 172.28.2.20 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 57204 -> 80 seq=1430078750 ack=0 win=64240
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=true ACK=false FIN=false RST=false PSH=false URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.2.20 -> 172.28.1.10 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 80 -> 57204 seq=2261989335 ack=1430078751 win=65160
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=true ACK=true FIN=false RST=false PSH=false URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.1.10 -> 172.28.2.20 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 57204 -> 80 seq=1430078751 ack=2261989336 win=502
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=false RST=false PSH=false URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.1.10 -> 172.28.2.20 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 57204 -> 80 seq=1430078751 ack=2261989336 win=502
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=false RST=false PSH=true URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 Payload (75 bytes): 474554202f20485454502f312e310d0a486f73743a203137322e32382e322e32300d0a557365722d4167656e743a206375726c2f382e31342e310d0a41636365
firewall-1  | 2025/10/19 15:18:47 …
firewall-1  | 2025/10/19 15:18:47
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.2.20 -> 172.28.1.10 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 80 -> 57204 seq=2261989336 ack=1430078826 win=509
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=false RST=false PSH=false URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.2.20 -> 172.28.1.10 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 80 -> 57204 seq=2261989336 ack=1430078826 win=509
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=false RST=false PSH=true URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 Payload (187 bytes): 485454502f312e3020323030204f4b0d0a5365727665723a2053696d706c65485454502f302e3620507974686f6e2f332e31322e31320d0a446174653a205375
firewall-1  | 2025/10/19 15:18:47 …
firewall-1  | 2025/10/19 15:18:47
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.1.10 -> 172.28.2.20 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 57204 -> 80 seq=1430078826 ack=2261989523 win=501
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=false RST=false PSH=false URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.2.20 -> 172.28.1.10 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 80 -> 57204 seq=2261989523 ack=1430078826 win=509
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=false RST=false PSH=true URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 Payload (114 bytes): 3c68746d6c3e3c626f64793e0a3c68313e56756c6e657261626c652054657374205365727665723c2f68313e0a3c703e496620796f752063616e207365652074
firewall-1  | 2025/10/19 15:18:47 …
firewall-1  | 2025/10/19 15:18:47
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.2.20 -> 172.28.1.10 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 80 -> 57204 seq=2261989637 ack=1430078826 win=509
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=true RST=false PSH=false URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.1.10 -> 172.28.2.20 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 57204 -> 80 seq=1430078826 ack=2261989637 win=501
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=false RST=false PSH=false URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.1.10 -> 172.28.2.20 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 57204 -> 80 seq=1430078826 ack=2261989638 win=501
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=true RST=false PSH=false URG=false ECE=false CWR=false NS=false
firewall-1  | 2025/10/19 15:18:47 IPv4 172.28.2.20 -> 172.28.1.10 proto=TCP ttl=63 ihl=5
firewall-1  | 2025/10/19 15:18:47 TCP 80 -> 57204 seq=2261989638 ack=1430078827 win=509
firewall-1  | 2025/10/19 15:18:47 Flags: SYN=false ACK=true FIN=false RST=false PSH=false URG=false ECE=false CWR=false NS=false
```

and ping:

```
firewall-1  | 2025/10/19 15:19:54
firewall-1  | 2025/10/19 15:19:54 IPv4 172.28.2.20 -> 172.28.1.10 proto=ICMPv4 ttl=63 ihl=5
firewall-1  | 2025/10/19 15:19:54 ICMPv4 type=0 code=0 checksum=0x6465
firewall-1  | 2025/10/19 15:19:54 Payload (56 bytes): ece9ae9e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
firewall-1  | 2025/10/19 15:19:54
```

The defense mechanism TCP state table has a web GUI that allows to see the table and verify that we actually defend from the SYN flood. You can access the GUI by visiting [http://localhost:8080](http://localhost:8080) on your browser. You should be able to verify that the flood attack is being rejected by the TCP state table.

Run test for SYN-cookies outside the docker environment by navigating to the server folder and running `go test -v`. There are tests to verify cookie creation, changing sequence number, and validating incoming cookies. The tests serve as an alternative to see if the implementation works swithout requiring it to be part of the server.

### Firewall Implementation

- Implemented in Go with nfqueue and gopacket library for packet manipulation.
- Linux netfilter to queue packets before they reach destination
- Parses IPv4, TCP, UDP and ICMP layers

### Client/Attack Simulator Implementation

- Implemented in Go with gopacket library for creating modified packets
- Simulates SYN flood DDoS attacks

### Server Implementation

- Implemented in python using http.server
- Vulnerable to SYN-floodsdue to lack of built in safety features and single thread

## Individual Contributions

### Vilhelm Prytz

- Docker setup and implementation (Docker Compose, Dockerfile and Docker Network and route all traffic through the firewall using `ip route`)
  - I setup the entire Docker setup, including writing a `docker-compose.yml` file, `Dockerfile`s for each component and Docket Networks allowing the components to communicate with eachother.
  - I wrote `ip route` commands inside the `entrypoint.sh` script for each component forcing them to route traffic via the firewall container.
- Firewall nfqueue feature
  - I implemented the initial structure for the `firewall` Go project.
  - I researched possible ways to intercept Go packets for the project and implemented `nfqueue`.
- README and documentation
  - Structure of README and initial documentation. We finalized the entire README together.
- Implement SYN flood client that sends SYN floods to specific IP and port based on input
  - I wrote a client that emulates a SYN flood attack using Go, gopacket.

### Jack Gugolz

- Packer parser
  - I used the Google-made package gopacket to make a packet parser. The packet parser allows us to log the packet type and corresponding flags, aswell as it's payload in the firewall.
- TCP State Table
  - I learnt what a TCP state table is, and how it can be used to protect against SYN floods.
  - I created the TCP state table, and implemented it in firewall.
- SYN Flood
  - I fixed the TCP headers in the TCP flood to make sure is was not filtered out by the state table.

### Tobias Bjurström

- Mynfqueue
  - Extension of nfqueue mainly used for debugging.
  - Implements a user-level queue in order to simplify logging the queue.
- SYN-cookies
  - Implementation of the SYN-cookies.
  - Built tests for verifying the functionality of the implementation.
- Web server
  - Starts a vulnerable server capable of serving requests but not inherently resistant to SYN-floods.

## References

- https://www.cloudflare.com/learning/ddos/what-is-an-ack-flood/
- https://www.fortinet.com/resources/cyberglossary/what-does-a-firewall-do
- https://www.radware.com/cyberpedia/application-security/7-most-common-attack-types/
- https://cheapskatesguide.org/articles/building-my-own-firewall.html
- https://www.geeksforgeeks.org/computer-networks/how-syn-cookies-are-used-to-preventing-syn-flood-attack/
