#!/bin/sh

ip route del default;
ip route add default via 172.28.1.254;
sleep infinity
