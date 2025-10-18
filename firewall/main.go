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
		if ip, tcp, plen, ok := decodeIPv4TCPWithPayload(data); ok {
			// 0) Drop obviously bad flag combos (stealth scans)
			if invalidTcpFlags(tcp) {
				log.Printf("DROP invalid-flags %s:%d -> %s:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
				verdict = nfqueue.NfDrop
				_ = nf.SetVerdict(id, verdict)
				return 0
			}

			src := ip4From(b4(ip.SrcIP))

			// 1) Temporary shun?
			tcpTable.mu.Lock()
			banned := tcpTable.isBanned(src)
			tcpTable.mu.Unlock()
			if banned {
				log.Printf("DROP banned %s", ip.SrcIP)
				verdict = nfqueue.NfDrop
				_ = nf.SetVerdict(id, verdict)
				return 0
			}

			// 2) SYN flood controls (only for initial SYNs)
			if tcp.SYN && !tcp.ACK {
				tcpTable.mu.Lock()
				// Per-IP rate
				synCount := tcpTable.bumpFixedWindow(tcpTable.synBySrc, src, tcpTable.synWindow)
				// Global half-open cap
				halfOpen := tcpTable.halfOpenCount()
				// Optional: promote to shun if way over limit
				if synCount > tcpTable.synPerIPLimit*4 {
					tcpTable.banned[src] = time.Now().Add(tcpTable.banDuration)
					log.Printf("BAN %s for %s (SYN rate %d/s)", ip.SrcIP, tcpTable.banDuration, synCount)
					tcpTable.mu.Unlock()
					verdict = nfqueue.NfDrop
					_ = nf.SetVerdict(id, verdict)
					return 0
				}
				dropSyn := synCount > tcpTable.synPerIPLimit || halfOpen >= tcpTable.globalHalfOpenLimit
				tcpTable.mu.Unlock()

				if dropSyn {
					log.Printf("DROP SYN-flood src=%s synRate=%d/s halfOpen=%d", ip.SrcIP, synCount, halfOpen)
					verdict = nfqueue.NfDrop
					_ = nf.SetVerdict(id, verdict)
					return 0
				}
			}

			// 3) RST throttling (common in floods)
			if tcp.RST {
				tcpTable.mu.Lock()
				rstCount := tcpTable.bumpFixedWindow(tcpTable.rstBySrc, src, tcpTable.rstWindow)
				over := rstCount > tcpTable.rstPerIPLimit
				tcpTable.mu.Unlock()
				if over {
					log.Printf("DROP RST-flood src=%s rstRate=%d/s", ip.SrcIP, rstCount)
					verdict = nfqueue.NfDrop
					_ = nf.SetVerdict(id, verdict)
					return 0
				}
			}

			// 4) No data until ESTABLISHED
			//    We allow only SYN/SYN-ACK/ACK during handshake. Any payload before ESTABLISHED is dropped.
			//    (Some TCP options carry data but gopacket separates them; plen>0 means app data)
			if plen > 0 {
				// Peek current state (best-effort) before Decide
				tcpTable.mu.Lock()
				preState := StateClosed
				if e := tcpTable.tab[FlowKey{b4(ip.SrcIP), b4(ip.DstIP), uint16(tcp.SrcPort), uint16(tcp.DstPort)}]; e != nil {
					preState = e.State
				} else if e := tcpTable.tab[FlowKey{b4(ip.DstIP), b4(ip.SrcIP), uint16(tcp.DstPort), uint16(tcp.SrcPort)}]; e != nil {
					preState = e.State
				}
				tcpTable.mu.Unlock()
				if preState != StateEstablished {
					log.Printf("DROP early-data %s:%d -> %s:%d state=%s payload=%d",
						ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, preState.String(), plen)
					verdict = nfqueue.NfDrop
					_ = nf.SetVerdict(id, verdict)
					return 0
				}
			}

			// 5) Normal state-machine decision
			accept, why, state := tcpTable.Decide(
				b4(ip.SrcIP), b4(ip.DstIP),
				uint16(tcp.SrcPort), uint16(tcp.DstPort),
				tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST,
			)

			log.Printf("TCP %s:%d -> %s:%d state=%s flags[S:%t A:%t F:%t R:%t] verdict=%s reason=%s",
				ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
				state.String(),
				tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST,
				map[bool]string{true: "ACCEPT", false: "DROP"}[accept],
				why,
			)

			if !accept {
				verdict = nfqueue.NfDrop
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
