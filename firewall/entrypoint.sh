#!/bin/ash

# add iptables rule to send packets to NFQUEUE
iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

# run our firewall
./firewall
