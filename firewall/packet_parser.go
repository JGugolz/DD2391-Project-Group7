package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parsePacket(b []byte) {
	var (
		ipv4    layers.IPv4
		tcp     layers.TCP
		udp     layers.UDP
		icmp    layers.ICMPv4
		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4,
		&ipv4, &tcp, &udp, &icmp, &payload,
	)
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(b, &decoded); err != nil {
		log.Printf("Decode error: %v", err)
	}

	for _, lt := range decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			fmt.Printf("IPv4 %s -> %s proto=%s ttl=%d ihl=%d\n",
				ipv4.SrcIP, ipv4.DstIP, ipv4.Protocol, ipv4.TTL, ipv4.IHL)

		case layers.LayerTypeTCP:
			fmt.Printf("TCP %d -> %d seq=%d ack=%d win=%d\n",
				tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, tcp.Window)

			fmt.Printf("Flags: SYN=%t ACK=%t FIN=%t RST=%t PSH=%t URG=%t ECE=%t CWR=%t NS=%t",
				tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST, tcp.PSH, tcp.URG, tcp.ECE, tcp.CWR, tcp.NS)

		case layers.LayerTypeUDP:
			fmt.Printf("UDP %d -> %d len=%d csum=0x%04x\n",
				udp.SrcPort, udp.DstPort, udp.Length, udp.Checksum)

		case layers.LayerTypeICMPv4:
			fmt.Printf("ICMPv4 type=%d code=%d checksum=0x%04x\n",
				icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Checksum)

		case gopacket.LayerTypePayload:
			const max = 64
			pl := payload
			if len(pl) > 0 {
				show := pl
				if len(show) > max {
					show = show[:max]
				}
				fmt.Printf("Payload (%d bytes): %x", len(pl), []byte(show))
				if len(pl) > max {
					fmt.Print("…")
				}
				fmt.Println()

			}
		}
	}
}
