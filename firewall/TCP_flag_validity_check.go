package main

import "github.com/google/gopacket/layers"

func invalidTcpFlags(t *layers.TCP) bool {
	// NULL scan: no flags set
	if !(t.SYN || t.ACK || t.FIN || t.RST || t.PSH || t.URG || t.ECE || t.CWR || t.NS) {
		return true
	}
	// SYN+FIN is nonsensical
	if t.SYN && t.FIN {
		return true
	}
	// Xmas scan: FIN+PSH+URG (classic)
	if t.FIN && t.PSH && t.URG && !t.SYN && !t.RST && !t.ACK {
		return true
	}
	// Header len sanity (gopacket already parses this, but double check)
	if t.DataOffset < 5 {
		return true
	}
	return false
}
