package main

import (
	"context"
	"fmt"
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
		parsePacket(*a.Payload)

		fmt.Printf("[%d]\t%v\n", id, *a.Payload)

		nf.SetVerdict(id, nfqueue.NfAccept)
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
