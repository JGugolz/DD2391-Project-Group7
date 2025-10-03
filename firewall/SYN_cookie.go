package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

var secretKey = []byte("supersecretkey")

// makeSynCookie generates a SYN cookie (sequence number)
func makeSynCookie(ip net.IP, port uint16, ts uint32) uint32 {
	h := hmac.New(sha256.New, secretKey)
	h.Write(ip)
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	h.Write(buf)
	timeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBuf, ts)
	h.Write(timeBuf)

	sum := h.Sum(nil)
	// Take lower 24 bits of hash, upper 8 bits store a timer value
	return (ts << 24) | (binary.BigEndian.Uint32(sum) & 0xFFFFFF)
}

// validateSynCookie checks if the cookie is valid
func validateSynCookie(cookie uint32, ip net.IP, port uint16) bool {
	ts := cookie >> 24
	expected := makeSynCookie(ip, port, ts)
	return expected == cookie
}

func main() {
	ip := net.ParseIP("192.168.0.10")
	port := uint16(54321)

	// Server "sends" SYN-ACK with a cookie as its sequence number
	ts := uint32(time.Now().Unix() / 60) // time-based, rotates every 60s
	cookie := makeSynCookie(ip, port, ts)
	fmt.Printf("Generated SYN cookie: %08x\n", cookie)

	// Later, client replies with ACK containing that cookie
	if validateSynCookie(cookie, ip, port) {
		fmt.Println("Cookie valid, establish connection.")
	} else {
		fmt.Println("Invalid cookie, drop packet.")
	}
}
