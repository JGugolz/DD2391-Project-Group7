package main

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestSynCookie_CreateAndValidate(t *testing.T) {
	// Enable SYN cookies for testing
	synCookieConfig.Enabled = true
	defer func() { synCookieConfig.Enabled = false }()

	srcIP := net.IPv4(192, 168, 1, 100)
	dstIP := net.IPv4(192, 168, 1, 1)
	srcPort := uint16(54321)
	dstPort := uint16(80)

	// Test 1: Generate and validate cookie
	cookie := GenerateSynCookie(srcIP, dstIP, srcPort, dstPort)

	if cookie == 0 {
		t.Error("Generated cookie should not be zero")
	}

	// Test 2: Validate the generated cookie
	isValid := ValidateSynCookie(cookie, srcIP, dstIP, srcPort, dstPort)
	if !isValid {
		t.Error("Generated cookie should be valid")
	}

	// Test 3: Different parameters should generate different cookies
	differentCookie := GenerateSynCookie(srcIP, dstIP, srcPort, uint16(443))
	if cookie == differentCookie {
		t.Error("Different ports should generate different cookies")
	}
}

func TestSynCookie_SequenceModification(t *testing.T) {
	synCookieConfig.Enabled = true
	defer func() { synCookieConfig.Enabled = false }()

	// Create a TCP SYN packet
	srcIP := net.IPv4(10, 0, 0, 1)
	dstIP := net.IPv4(10, 0, 0, 2)
	srcPort := uint16(32768)
	dstPort := uint16(8080)

	packet := createTestSYNPacket(srcIP, dstIP, srcPort, dstPort, 123456789)

	// Generate SYN cookie
	cookie := GenerateSynCookie(srcIP, dstIP, srcPort, dstPort)

	// Modify the sequence number with the cookie
	modifiedPacket, err := ModifyTCPSequenceNumber(packet, cookie)
	if err != nil {
		t.Fatalf("Failed to modify sequence number: %v", err)
	}

	// Parse the modified packet and verify the sequence number
	ip, tcp, ok := decodeIPv4TCP(modifiedPacket)
	if !ok {
		t.Fatal("Failed to decode modified packet")
	}

	if tcp.Seq != cookie {
		t.Errorf("Sequence number not properly modified. Expected: %d, Got: %d", cookie, tcp.Seq)
	}

	// Verify IP addresses are preserved
	if !ip.SrcIP.Equal(srcIP) || !ip.DstIP.Equal(dstIP) {
		t.Error("IP addresses should be preserved during sequence modification")
	}
}

func TestSynCookie_Validation(t *testing.T) {
	synCookieConfig.Enabled = true
	defer func() { synCookieConfig.Enabled = false }()

	srcIP := net.IPv4(172, 16, 1, 50)
	dstIP := net.IPv4(172, 16, 1, 1)
	srcPort := uint16(50000)
	dstPort := uint16(80)

	// Test valid cookie
	validCookie := GenerateSynCookie(srcIP, dstIP, srcPort, dstPort)
	if !ValidateSynCookie(validCookie, srcIP, dstIP, srcPort, dstPort) {
		t.Error("Valid cookie should pass validation")
	}

	// Test invalid cookie
	if ValidateSynCookie(123456, srcIP, dstIP, srcPort, dstPort) {
		t.Error("Invalid cookie should fail validation")
	}

	// Test with wrong source IP
	wrongIP := net.IPv4(172, 16, 1, 99)
	wrongCookie := GenerateSynCookie(wrongIP, dstIP, srcPort, dstPort)
	if ValidateSynCookie(wrongCookie, srcIP, dstIP, srcPort, dstPort) {
		t.Error("Cookie with wrong source IP should fail validation")
	}
}

func TestSynCookie_EnableDisable(t *testing.T) {
	// Test disabled state
	synCookieConfig.Enabled = false
	if ShouldUseSynCookies() {
		t.Error("ShouldUseSynCookies should return false when disabled")
	}

	// Test enabled state
	synCookieConfig.Enabled = true
	if !ShouldUseSynCookies() {
		t.Error("ShouldUseSynCookies should return true when enabled")
	}
}

func TestSynCookie_SecretRotation(t *testing.T) {
	synCookieConfig.Enabled = true
	defer func() { synCookieConfig.Enabled = false }()

	srcIP := net.IPv4(192, 168, 0, 1)
	dstIP := net.IPv4(192, 168, 0, 2)
	srcPort := uint16(12345)
	dstPort := uint16(80)

	// Generate cookie with current secret
	cookie1 := GenerateSynCookie(srcIP, dstIP, srcPort, dstPort)

	// Simulate secret rotation by manually updating
	oldSecret := synCookieConfig.Secret
	var newSecret [16]byte
	copy(newSecret[:], []byte("new-secret-123456"))
	synCookieConfig.Secret = newSecret
	synCookieConfig.LastSecretRotate = time.Now()

	// Generate cookie with new secret
	cookie2 := GenerateSynCookie(srcIP, dstIP, srcPort, dstPort)

	// Cookies should be different with different secrets
	if cookie1 == cookie2 {
		t.Error("Cookies should be different after secret rotation")
	}

	// Restore old secret for validation test
	synCookieConfig.Secret = oldSecret
	if !ValidateSynCookie(cookie1, srcIP, dstIP, srcPort, dstPort) {
		t.Error("Cookie should validate with correct secret")
	}
}

func TestSynCookie_DifferentConnections(t *testing.T) {
	synCookieConfig.Enabled = true
	defer func() { synCookieConfig.Enabled = false }()

	// Test multiple connections get different cookies
	connections := []struct {
		srcIP   net.IP
		dstIP   net.IP
		srcPort uint16
		dstPort uint16
	}{
		{net.IPv4(10, 1, 1, 1), net.IPv4(10, 1, 1, 2), 1000, 80},
		{net.IPv4(10, 1, 1, 3), net.IPv4(10, 1, 1, 2), 1001, 80},
		{net.IPv4(10, 1, 1, 1), net.IPv4(10, 1, 1, 2), 1000, 443},
	}

	cookies := make([]uint32, len(connections))
	for i, conn := range connections {
		cookies[i] = GenerateSynCookie(conn.srcIP, conn.dstIP, conn.srcPort, conn.dstPort)
	}

	// All cookies should be unique
	for i := 0; i < len(cookies); i++ {
		for j := i + 1; j < len(cookies); j++ {
			if cookies[i] == cookies[j] {
				t.Errorf("Cookies for different connections should be unique: %d and %d", i, j)
			}
		}
	}
}

// Helper function to create test SYN packets
func createTestSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32) []byte {
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
		IHL:      5,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		SYN:     true,
		Window:  65535,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tcp.SetNetworkLayerForChecksum(ip)
	gopacket.SerializeLayers(buf, opts, ip, tcp)

	return buf.Bytes()
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
