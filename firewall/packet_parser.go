package main

import (
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
			log.Printf("IPv4 %s -> %s proto=%s ttl=%d ihl=%d\n",
				ipv4.SrcIP, ipv4.DstIP, ipv4.Protocol, ipv4.TTL, ipv4.IHL)

		case layers.LayerTypeTCP:
			log.Printf("TCP %d -> %d seq=%d ack=%d win=%d\n",
				tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, tcp.Window)

			log.Printf("Flags: SYN=%t ACK=%t FIN=%t RST=%t PSH=%t URG=%t ECE=%t CWR=%t NS=%t\n",
				tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST, tcp.PSH, tcp.URG, tcp.ECE, tcp.CWR, tcp.NS)

		case layers.LayerTypeUDP:
			log.Printf("UDP %d -> %d len=%d csum=0x%04x\n",
				udp.SrcPort, udp.DstPort, udp.Length, udp.Checksum)

		case layers.LayerTypeICMPv4:
			log.Printf("ICMPv4 type=%d code=%d checksum=0x%04x\n",
				icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Checksum)

		case gopacket.LayerTypePayload:
			const max = 64
			pl := payload
			if len(pl) > 0 {
				show := pl
				if len(show) > max {
					show = show[:max]
				}
				log.Printf("Payload (%d bytes): %x", len(pl), []byte(show))
				if len(pl) > max {
					log.Print("…")
				}
				log.Println()
			}
		}
	}
}

func decodeIPv4TCP(b []byte) (ip *layers.IPv4, tcp *layers.TCP, ok bool) {
	var (
		ipv4 layers.IPv4
		t    layers.TCP
	)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4,
		&ipv4, &t,
	)
	var decoded []gopacket.LayerType
	if err := parser.DecodeLayers(b, &decoded); err != nil {
		// non-fatal
	}
	hasIP, hasTCP := false, false
	for _, lt := range decoded {
		if lt == layers.LayerTypeIPv4 {
			hasIP = true
		}
		if lt == layers.LayerTypeTCP {
			hasTCP = true
		}
	}
	if hasIP && hasTCP {
		return &ipv4, &t, true
	}
	return nil, nil, false
}

func decodeIPv4TCPWithPayload(b []byte) (ip *layers.IPv4, tcp *layers.TCP, payloadLen int, ok bool) {
	var (
		ipv4 layers.IPv4
		t    layers.TCP
		pl   gopacket.Payload
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipv4, &t, &pl)
	var decoded []gopacket.LayerType
	_ = parser.DecodeLayers(b, &decoded)
	hasIP, hasTCP := false, false
	for _, lt := range decoded {
		if lt == layers.LayerTypeIPv4 {
			hasIP = true
		}
		if lt == layers.LayerTypeTCP {
			hasTCP = true
		}
		if lt == gopacket.LayerTypePayload {
			payloadLen = len(pl)
		}
	}
	if hasIP && hasTCP {
		return &ipv4, &t, payloadLen, true
	}
	return nil, nil, 0, false
}

func decodeIPv4(b []byte) (*layers.IPv4, bool) {
	var ip layers.IPv4
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip)
	var decoded []gopacket.LayerType
	_ = parser.DecodeLayers(b, &decoded)
	for _, lt := range decoded {
		if lt == layers.LayerTypeIPv4 {
			return &ip, true
		}
	}
	return nil, false
}
