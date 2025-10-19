# DD2391-Project-Group7

## Problem Statement

Networks face various types of attacks including DDoS attacks, such as ACK floods or SYN floods. Filtering these types of attack is crucial when building a firewall. This project implements a lab which consists of a custom firewall, to demonstrate packet interception, parsing it, and filtering for attacks such as SYN floods. The project also includes an attack simulator inside a Docker network to demonstrate and test the firewall.

## Technical Description

The project consist of a server (web server, target), client (attack simulator) and firewall.

The entire project runs inside Docker network where each component has a specific IP addresses within 172.28.x.x. The firewall that we have created should accept or decline packets. The IP adress that is used is 172.28.1.254 and can be pinged by using `ping 172.28.1.254`.

### How to use

To run this lab, you need to have Docker installed. You can install it [here](https://docs.docker.com/engine/install/), or you can install Docker Desktop.

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

You know have a shell inside the `client` container. If you try to ping stuff from here, you should see your packets being processed by the firewall in the first terminal.

You can run the SYN flood by running `./client`.

### Firewall Implementation

- Implemented in Go with nfqueue and gopacket library for packet manipulation.
- Linux netfilter to queue packets before they reach destination
- Parses IPv4, TCP, UDP and ICMP layers

### Client/Attack Simulator Implementation

- Implemented in Go with gopacket library for creating modified packets
- Simulates SYN flood DDoS attacks

### Server Implementation

- TBD

## Individual Contributions

### Vilhelm Prytz

### Jack Gugolz

### Tobias Bjurström

## References

- https://www.cloudflare.com/learning/ddos/what-is-an-ack-flood/
- https://www.fortinet.com/resources/cyberglossary/what-does-a-firewall-do
- https://www.radware.com/cyberpedia/application-security/7-most-common-attack-types/
- https://cheapskatesguide.org/articles/building-my-own-firewall.html
