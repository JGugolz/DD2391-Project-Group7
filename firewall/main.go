package main

import (
	"context"
	"fmt"
	"log"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

var tcpTable = NewStateTable()

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
		if a.PacketID == nil || a.Payload == nil {
			return 0
		}
		id := *a.PacketID
		data := *a.Payload

		// (Optional) compact debug:
		if len(data) >= 10 {
			log.Printf("NFQ id=%d proto=%d len=%d", id, int(data[9]), len(data))
		}

		// Human-readable decode (your function)
		parsePacket(data)

		verdict := nfqueue.NfAccept

		// Stronger TCP path
		if ip, tcp, _, ok := decodeIPv4TCPWithPayload(data); ok {
			// 0) Drop obviously bad flag combos (stealth scans)
			if invalidTcpFlags(tcp) {
				log.Printf("DROP invalid-flags %s:%d -> %s:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
				verdict = nfqueue.NfDrop
				_ = nf.SetVerdict(id, verdict)
				return 0
			}
		}

		if err := nf.SetVerdict(id, verdict); err != nil {
			log.Printf("SetVerdict error id=%d: %v", id, err)
		}
		return 0
	}

	// Register function to listen on nflqueue queue 100
	err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		fmt.Println(err)
		return -1
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	startHTTP()

	// Block until the context expires
	<-ctx.Done()
}
