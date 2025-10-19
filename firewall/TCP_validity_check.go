package main

import "github.com/google/gopacket/layers"

func invalidTcpPacket(t *layers.TCP) bool {
	// NULL scan: no flags set
	if !(t.SYN || t.ACK || t.FIN || t.RST || t.PSH || t.URG || t.ECE || t.CWR || t.NS) {
		return true
	}
	// SYN+FIN is nonsensical
	if t.SYN && t.FIN {
		return true
	}
	// Xmas scan: FIN+PSH+URG
	if t.FIN && t.PSH && t.URG && !t.SYN && !t.RST && !t.ACK {
		return true
	}
	// Header len sanity
	if t.DataOffset < 5 {
		return true
	}
	return false
}
