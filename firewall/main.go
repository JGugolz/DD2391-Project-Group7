package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

func main() {
	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      0,     // Use queue 0, which is the default queue
		MaxPacketLen: 65535, // 0xFFFF,
		MaxQueueLen:  255,   // 0xFF
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	// Avoid receiving ENOBUFS errors.
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		fmt.Printf("failed to set netlink option %v: %v\n",
			netlink.NoENOBUFS, err)
		return
	}

	ctx := context.Background()

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		// Just print out the id and payload of the nfqueue packet
		// fmt.Printf("[%v]", *a.Timestamp)
		fmt.Printf("[%d]\t%v\n", id, *a.Payload)

		// ---- IPv4 header ----
		if len(*a.Payload) < 20 {
			panic("too short for IPv4 header")
		}
		vihl := (*a.Payload)[0]
		version := vihl >> 4
		ihl := int(vihl&0x0F) * 4
		tlen := binary.BigEndian.Uint16((*a.Payload)[2:4])
		proto := (*a.Payload)[9]
		src := net.IP((*a.Payload)[12:16])
		dst := net.IP((*a.Payload)[16:20])

		if version != 4 {
			panic("not IPv4")
		}
		if len(*a.Payload) < int(tlen) || len(*a.Payload) < ihl {
			panic("truncated packet")
		}

		fmt.Printf("IPv4: ver=%d ihl=%dB total_len=%d proto=%d src=%s dst=%s\n",
			version, ihl, tlen, proto, src, dst)

		if proto != 6 {
			fmt.Println("Not TCP.")
		}

		// ---- TCP header ----
		tcp := (*a.Payload)[ihl:]
		if len(tcp) < 20 {
			panic("too short for TCP header")
		}
		sport := binary.BigEndian.Uint16(tcp[0:2])
		dport := binary.BigEndian.Uint16(tcp[2:4])
		seq := binary.BigEndian.Uint32(tcp[4:8])
		ack := binary.BigEndian.Uint32(tcp[8:12])
		dofsAndFlags := binary.BigEndian.Uint16(tcp[12:14])
		dataOffset := int((dofsAndFlags>>12)&0xF) * 4
		flags := dofsAndFlags & 0x01FF // 9 bits of flags
		win := binary.BigEndian.Uint16(tcp[14:16])
		chk := binary.BigEndian.Uint16(tcp[16:18])
		urg := binary.BigEndian.Uint16(tcp[18:20])

		if len(tcp) < dataOffset {
			panic("truncated TCP header + options")
		}

		fmt.Printf("TCP: %d -> %d seq=%d ack=%d win=%d cksum=0x%04x urg=%d\n",
			sport, dport, seq, ack, win, chk, urg)

		// decode flags
		const (
			NS  = 1 << 8
			CWR = 1 << 7
			ECE = 1 << 6
			URG = 1 << 5
			ACK = 1 << 4
			PSH = 1 << 3
			RST = 1 << 2
			SYN = 1 << 1
			FIN = 1 << 0
		)
		fmt.Printf("Flags: NS=%t CWR=%t ECE=%t URG=%t ACK=%t PSH=%t RST=%t SYN=%t FIN=%t\n",
			flags&NS != 0, flags&CWR != 0, flags&ECE != 0, flags&URG != 0,
			flags&ACK != 0, flags&PSH != 0, flags&RST != 0, flags&SYN != 0, flags&FIN != 0)

		// ---- TCP options (if any) ----
		opts := tcp[20:dataOffset]
		if len(opts) > 0 {
			fmt.Printf("TCP options (%d bytes): %v\n", len(opts), opts)
			// Parse a few common ones
			for i := 0; i < len(opts); {
				kind := opts[i]
				if kind == 0 { // End of options
					fmt.Println("  EOL")
					break
				}
				if kind == 1 { // NOP
					fmt.Println("  NOP")
					i++
					continue
				}
				if i+1 >= len(opts) {
					fmt.Println("  (truncated option)")
					break
				}
				olen := int(opts[i+1])
				if olen < 2 || i+olen > len(opts) {
					fmt.Println("  (bad option length)")
					break
				}
				body := opts[i+2 : i+olen]
				switch kind {
				case 8: // Timestamps
					if len(body) == 8 {
						tsval := binary.BigEndian.Uint32(body[:4])
						tsecr := binary.BigEndian.Uint32(body[4:])
						fmt.Printf("  TSopt: TSval=%d TSecr=%d\n", tsval, tsecr)
					} else {
						fmt.Printf("  TSopt (len=%d)\n", len(body))
					}
				default:
					fmt.Printf("  Option kind=%d len=%d body=%v\n", kind, olen, body)
				}
				i += olen
			}
		}

		// ---- TCP payload (application data) ----
		payload := tcp[dataOffset : int(tlen)-ihl]
		fmt.Printf("TCP payload: %d bytes\n", len(payload))
		if len(payload) > 0 {
			fmt.Printf("% x\n", payload)
		}

		nf.SetVerdict(id, nfqueue.NfAccept)
		// nf.SetVerdict(id, nfqueue.NfDrop)
		return 0
	}

	// Register your function to listen on nflqueue queue 100
	err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		fmt.Println(err)
		return -1
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}
