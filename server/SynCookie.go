package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
The variable Enabled in synCookieConfig is used to enable/disable the syn-cookie functionalities in main.go

Simple syn-cookie consists of setting the sequence number to a hashed value consisting of IPs and Ports
(See example from wikipedia, without  t and m)
*/

// SYN Cookie configuration
type SynCookieConfig struct {
	Enabled          bool
	Secret           [16]byte      // Secret for cookie generation
	SecretRotate     time.Duration // How often to rotate secret
	LastSecretRotate time.Time
	SequenceMask     uint32 // Mask for sequence numbers
}

var synCookieConfig = SynCookieConfig{
	Enabled:      false,
	SecretRotate: time.Hour,
	SequenceMask: 0x00FFFFFF, // 24 bits for counter
}

// Initialize SYN cookie secret
func init() {
	rand.Seed(time.Now().UnixNano())
	updateSynCookieSecret()
}

func updateSynCookieSecret() {
	rand.Read(synCookieConfig.Secret[:])
	synCookieConfig.LastSecretRotate = time.Now()
}

// Generate SYN cookie for a connection
func GenerateSynCookie(srcIP, dstIP net.IP, srcPort, dstPort uint16) uint32 {
	if time.Since(synCookieConfig.LastSecretRotate) > synCookieConfig.SecretRotate {
		updateSynCookieSecret()
	}

	h := sha1.New()
	h.Write(synCookieConfig.Secret[:])
	h.Write(srcIP.To4())
	h.Write(dstIP.To4())
	binary.Write(h, binary.BigEndian, srcPort)
	binary.Write(h, binary.BigEndian, dstPort)

	hash := h.Sum(nil)
	cookie := binary.BigEndian.Uint32(hash[:4]) & 0x7FFFFFFF // Use 31 bits to avoid sign issues

	return cookie
}

// ModifyTCPSequenceNumber changes the TCP sequence number and recalculates checksums
func ModifyTCPSequenceNumber(data []byte, newSeq uint32) ([]byte, error) {
	// Parse data
	ip, tcp, payload, ok := decodeIPv4TCPWithFullPayload(data)
	if !ok {
		return nil, fmt.Errorf("failed to decode packet")
	}

	// Create new TCP layer with modified sequence
	newTCP := &layers.TCP{
		SrcPort:    tcp.SrcPort,
		DstPort:    tcp.DstPort,
		Seq:        newSeq,
		Ack:        tcp.Ack,
		DataOffset: tcp.DataOffset,
		FIN:        tcp.FIN,
		SYN:        tcp.SYN,
		RST:        tcp.RST,
		PSH:        tcp.PSH,
		ACK:        tcp.ACK,
		URG:        tcp.URG,
		ECE:        tcp.ECE,
		CWR:        tcp.CWR,
		NS:         tcp.NS,
		Window:     tcp.Window,
		Urgent:     tcp.Urgent,
		Options:    tcp.Options,
	}

	// Set the network layer for checksum calculation
	newTCP.SetNetworkLayerForChecksum(ip)

	// Serialize with automatic checksum computation
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Rebuild the packet
	err := gopacket.SerializeLayers(buffer, opts,
		ip,
		newTCP,
		gopacket.Payload(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("serialize failed: %v", err)
	}

	return buffer.Bytes(), nil
}

// Validate SYN cookie
func ValidateSynCookie(cookie uint32, srcIP, dstIP net.IP, srcPort, dstPort uint16) bool {
	expected := GenerateSynCookie(dstIP, srcIP, dstPort, srcPort)
	log.Printf("SYN-COOKIE: Expected %d, Sent %d", expected, cookie)
	isValid := cookie == expected
	if isValid {
		log.Printf("SYN-COOKIE: Valid cookie from client")
	} else {
		log.Printf("SYN-COOKIE: Invalid cookie from client")
	}
	return isValid
}

// Check if we should use SYN cookies
func ShouldUseSynCookies() bool {
	if !synCookieConfig.Enabled {
		return false
	}
	return true
}
