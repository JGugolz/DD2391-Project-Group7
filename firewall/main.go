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
		// Safety: attributes are pointers
		if a.PacketID == nil || a.Payload == nil {
			return nfqueue.NfAccept
		}
		id := *a.PacketID
		data := *a.Payload

		ip, tcp, ok := decodeIPv4TCP(data)
		if !ok {
			return nfqueue.NfAccept
		}

		accept, why, state := tcpTable.Decide(
			b4(ip.SrcIP), b4(ip.DstIP),
			uint16(tcp.SrcPort), uint16(tcp.DstPort),
			tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST,
		)

		log.Printf("id=%d %s:%d -> %s:%d state=%s flags[S:%t A:%t F:%t R:%t] verdict=%s reason=%s",
			id, ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
			state.String(),
			tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST,
			map[bool]string{true: "ACCEPT", false: "DROP"}[accept],
			why,
		)

		if accept {
			return nfqueue.NfAccept
		}
		return nfqueue.NfDrop
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

	// Block until the context expires
	<-ctx.Done()
}
