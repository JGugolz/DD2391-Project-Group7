#!/bin/sh

# Set up routing
ip route del default
ip route add default via 172.28.2.254

# Start Python HTTP server
echo "Starting Python HTTP server on 172.28.2.20:80..."
exec python3 -m http.server 80
