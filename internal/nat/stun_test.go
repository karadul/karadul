package nat

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// startMockSTUNServer listens on a random UDP port and replies to Binding
// Requests with a Binding Response that XOR-reflects the sender's address.
// Call stop() to shut the server down.
func startMockSTUNServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr = srv.LocalAddr().String()
	quit := make(chan struct{})
	go func() {
		defer srv.Close()
		buf := make([]byte, 1024)
		for {
			select {
			case <-quit:
				return
			default:
			}
			_ = srv.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, src, err := srv.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if n < stunHeaderSize {
				continue
			}
			msgType := binary.BigEndian.Uint16(buf[0:])
			if msgType != stunMsgTypeBindingRequest {
				continue
			}
			txID := make([]byte, 12)
			copy(txID, buf[8:20])
			resp := buildMockBindingResponse(txID, src)
			if resp != nil {
				_, _ = srv.WriteToUDP(resp, src)
			}
		}
	}()
	stop = func() { close(quit) }
	return addr, stop
}

// buildMockBindingResponse constructs a STUN Binding Response with
// XOR-MAPPED-ADDRESS set to reflect src.
func buildMockBindingResponse(txID []byte, src *net.UDPAddr) []byte {
	ip4 := src.IP.To4()
	if ip4 == nil {
		return nil
	}

	magicBytes := [4]byte{0x21, 0x12, 0xA4, 0x42}
	xorIP := [4]byte{
		ip4[0] ^ magicBytes[0],
		ip4[1] ^ magicBytes[1],
		ip4[2] ^ magicBytes[2],
		ip4[3] ^ magicBytes[3],
	}
	xorPort := uint16(src.Port) ^ uint16(stunMagicCookie>>16)

	// XOR-MAPPED-ADDRESS value: reserved(1)+family(1)+xor-port(2)+xor-ip(4) = 8 bytes.
	val := make([]byte, 8)
	val[0] = 0x00
	val[1] = stunAddrFamilyIPv4
	binary.BigEndian.PutUint16(val[2:], xorPort)
	copy(val[4:], xorIP[:])

	// Attribute TLV: type(2)+len(2)+value(8) = 12 bytes.
	attrLen := len(val)
	tlv := make([]byte, 4+attrLen)
	binary.BigEndian.PutUint16(tlv[0:], stunAttrXORMappedAddress)
	binary.BigEndian.PutUint16(tlv[2:], uint16(attrLen))
	copy(tlv[4:], val)

	resp := make([]byte, stunHeaderSize+len(tlv))
	binary.BigEndian.PutUint16(resp[0:], stunMsgTypeBindingResponse)
	binary.BigEndian.PutUint16(resp[2:], uint16(len(tlv)))
	binary.BigEndian.PutUint32(resp[4:], stunMagicCookie)
	copy(resp[8:20], txID)
	copy(resp[stunHeaderSize:], tlv)
	return resp
}

// TestBindingRequest_XORMappedAddress verifies that BindingRequest correctly
// decodes the XOR-MAPPED-ADDRESS echoed by the mock server.
func TestBindingRequest_XORMappedAddress(t *testing.T) {
	serverAddr, stop := startMockSTUNServer(t)
	defer stop()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	result, err := BindingRequest(conn, serverAddr)
	if err != nil {
		t.Fatalf("BindingRequest: %v", err)
	}
	if !result.PublicAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("IP: want 127.0.0.1, got %s", result.PublicAddr.IP)
	}
	if result.PublicAddr.Port == 0 {
		t.Error("port should not be zero")
	}
	if result.ServerAddr != serverAddr {
		t.Errorf("ServerAddr: want %q, got %q", serverAddr, result.ServerAddr)
	}
}

// TestBindingRequest_Timeout verifies that BindingRequest returns an error
// when the server does not respond (port closed / no response).
func TestBindingRequest_Timeout(t *testing.T) {
	// Listen briefly and then close — the port will be closed before the client sends.
	dummy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	dummyAddr := dummy.LocalAddr().String()
	dummy.Close() // close immediately so no response arrives

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = BindingRequest(conn, dummyAddr)
	if err == nil {
		t.Fatal("expected error for unresponsive server")
	}
}

// TestBindingRequest_BadMsgType verifies that a response with an unexpected
// message type is rejected.
func TestBindingRequest_BadMsgType(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	quit := make(chan struct{})
	go func() {
		defer srv.Close()
		buf := make([]byte, 1024)
		for {
			select {
			case <-quit:
				return
			default:
			}
			_ = srv.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, src, err := srv.ReadFromUDP(buf)
			if err != nil || n < stunHeaderSize {
				continue
			}
			// Send back wrong type.
			resp := make([]byte, stunHeaderSize)
			binary.BigEndian.PutUint16(resp[0:], 0xFFFF)
			binary.BigEndian.PutUint32(resp[4:], stunMagicCookie)
			copy(resp[8:20], buf[8:20])
			_, _ = srv.WriteToUDP(resp, src)
		}
	}()
	defer close(quit)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = BindingRequest(conn, srv.LocalAddr().String())
	if err == nil {
		t.Fatal("expected error for bad message type")
	}
}

// TestParseBindingResponse_TxIDMismatch verifies that a response with a
// non-matching transaction ID is rejected.
func TestParseBindingResponse_TxIDMismatch(t *testing.T) {
	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = 0xAA
	}
	resp := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(resp[0:], stunMsgTypeBindingResponse)
	binary.BigEndian.PutUint32(resp[4:], stunMagicCookie)
	for i := 8; i < 20; i++ {
		resp[i] = 0xBB // different
	}
	if _, err := parseBindingResponse(resp, txID); err == nil {
		t.Fatal("expected txID mismatch error")
	}
}

// TestParseBindingResponse_MappedAddress verifies MAPPED-ADDRESS parsing.
func TestParseBindingResponse_MappedAddress(t *testing.T) {
	txID := make([]byte, 12)
	val := []byte{
		0x00, stunAddrFamilyIPv4,
		0x10, 0xE1, // port 4321
		192, 168, 1, 5,
	}
	tlv := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(tlv[0:], stunAttrMappedAddress)
	binary.BigEndian.PutUint16(tlv[2:], uint16(len(val)))
	copy(tlv[4:], val)

	resp := make([]byte, stunHeaderSize+len(tlv))
	binary.BigEndian.PutUint16(resp[0:], stunMsgTypeBindingResponse)
	binary.BigEndian.PutUint16(resp[2:], uint16(len(tlv)))
	binary.BigEndian.PutUint32(resp[4:], stunMagicCookie)
	copy(resp[8:20], txID)
	copy(resp[stunHeaderSize:], tlv)

	addr, err := parseBindingResponse(resp, txID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.Port != 4321 {
		t.Errorf("port: want 4321, got %d", addr.Port)
	}
	if !addr.IP.Equal(net.IPv4(192, 168, 1, 5)) {
		t.Errorf("IP: want 192.168.1.5, got %s", addr.IP)
	}
}

// TestParseMappedAddress_IPv6 verifies parseMappedAddress handles IPv6 addresses.
func TestParseMappedAddress_IPv6(t *testing.T) {
	b := make([]byte, 20) // 4 header + 16 IPv6
	b[1] = stunAddrFamilyIPv6
	binary.BigEndian.PutUint16(b[2:], 12345) // port
	// IPv6 address at b[4:20]
	copy(b[4:], net.IPv6loopback)

	addr, err := parseMappedAddress(b)
	if err != nil {
		t.Fatalf("parseMappedAddress IPv6: %v", err)
	}
	if addr.Port != 12345 {
		t.Errorf("port: want 12345, got %d", addr.Port)
	}
	if !addr.IP.Equal(net.IPv6loopback) {
		t.Errorf("IP: want ::1, got %s", addr.IP)
	}
}

// TestParseMappedAddress_TooShort verifies parseMappedAddress returns error for short buffers.
func TestParseMappedAddress_TooShort(t *testing.T) {
	if _, err := parseMappedAddress([]byte{0x00, stunAddrFamilyIPv4, 0x10}); err == nil {
		t.Fatal("expected error for too-short buffer")
	}
}

// TestParseMappedAddress_IPv6_TooShort verifies parseMappedAddress errors when IPv6 data is missing.
func TestParseMappedAddress_IPv6_TooShort(t *testing.T) {
	b := make([]byte, 8) // only 4 bytes of addr, not 16
	b[1] = stunAddrFamilyIPv6
	binary.BigEndian.PutUint16(b[2:], 9000)
	copy(b[4:], net.IPv4(1, 2, 3, 4)) // 4 bytes only
	if _, err := parseMappedAddress(b); err == nil {
		t.Fatal("expected error for IPv6 with too-short buffer")
	}
}

// TestParseMappedAddress_UnknownFamily verifies parseMappedAddress returns error for unknown family.
func TestParseMappedAddress_UnknownFamily(t *testing.T) {
	b := make([]byte, 8)
	b[1] = 0xFF // unknown family
	binary.BigEndian.PutUint16(b[2:], 80)
	if _, err := parseMappedAddress(b); err == nil {
		t.Fatal("expected error for unknown address family")
	}
}

// TestParseBindingResponse_NoMappedAddress verifies that a response with no
// address attribute is rejected.
func TestParseBindingResponse_NoMappedAddress(t *testing.T) {
	txID := make([]byte, 12)
	resp := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(resp[0:], stunMsgTypeBindingResponse)
	binary.BigEndian.PutUint32(resp[4:], stunMagicCookie)
	copy(resp[8:20], txID)

	if _, err := parseBindingResponse(resp, txID); err == nil {
		t.Fatal("expected error for missing mapped address")
	}
}

// TestParseBindingResponse_Truncated verifies that a response claiming more
// attribute data than exists is rejected.
func TestParseBindingResponse_Truncated(t *testing.T) {
	txID := make([]byte, 12)
	resp := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(resp[0:], stunMsgTypeBindingResponse)
	// Claim 100 bytes of attributes but send none.
	binary.BigEndian.PutUint16(resp[2:], 100)
	binary.BigEndian.PutUint32(resp[4:], stunMagicCookie)
	copy(resp[8:20], txID)

	if _, err := parseBindingResponse(resp, txID); err == nil {
		t.Fatal("expected error for truncated response")
	}
}

// TestParseXORMappedAddress_IPv6 verifies IPv6 XOR-MAPPED-ADDRESS decoding.
func TestParseXORMappedAddress_IPv6(t *testing.T) {
	// Build a 20-byte IPv6 XOR-MAPPED-ADDRESS attribute.
	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(i)
	}

	// Expected IP = 2001:db8::1
	expectedIP := net.ParseIP("2001:db8::1").To16()
	// XOR key: magic cookie (4 bytes) + txID (12 bytes)
	xorKey := make([]byte, 16)
	binary.BigEndian.PutUint32(xorKey[0:], stunMagicCookie)
	copy(xorKey[4:], txID)

	b := make([]byte, 20)
	b[1] = stunAddrFamilyIPv6
	// XOR port with high 16 bits of magic cookie.
	xorPort := uint16(12345) ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(b[2:], xorPort)
	// XOR IP with xorKey.
	for i := 0; i < 16; i++ {
		b[4+i] = expectedIP[i] ^ xorKey[i]
	}

	addr, err := parseXORMappedAddress(b, txID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !addr.IP.Equal(expectedIP) {
		t.Errorf("IP mismatch: got %s, want %s", addr.IP, expectedIP)
	}
	if addr.Port != 12345 {
		t.Errorf("port mismatch: got %d, want 12345", addr.Port)
	}
}

// TestParseXORMappedAddress_TooShort verifies parseXORMappedAddress returns
// error when the buffer is too small.
func TestParseXORMappedAddress_TooShort(t *testing.T) {
	if _, err := parseXORMappedAddress([]byte{0x00, stunAddrFamilyIPv4, 0x10}, nil); err == nil {
		t.Fatal("expected error for too-short XOR mapped address buffer")
	}
}

// TestBindingRequest_InvalidServerAddr verifies BindingRequest returns an error
// when the server address cannot be resolved (covers line 40-42).
func TestBindingRequest_InvalidServerAddr(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = BindingRequest(conn, "not-a-valid-addr:xyz")
	if err == nil {
		t.Fatal("expected resolve error for invalid server address")
	}
}
