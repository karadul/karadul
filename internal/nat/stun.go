// Package nat implements STUN-based NAT type detection and UDP hole punching.
// STUN implementation follows RFC 5389 (Binding Request/Response only).
package nat

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	stunMsgTypeBindingRequest  = 0x0001
	stunMsgTypeBindingResponse = 0x0101
	stunMsgTypeBindingError    = 0x0111

	stunMagicCookie = 0x2112A442

	stunAttrMappedAddress    = 0x0001
	stunAttrXORMappedAddress = 0x0020

	stunAddrFamilyIPv4 = 0x01
	stunAddrFamilyIPv6 = 0x02

	stunHeaderSize  = 20
	stunDialTimeout = 3 * time.Second
)

// BindingResult holds the public endpoint discovered via STUN.
type BindingResult struct {
	PublicAddr *net.UDPAddr
	ServerAddr string
}

// BindingRequest sends a STUN Binding Request to serverAddr and returns the
// public endpoint (XOR-MAPPED-ADDRESS or MAPPED-ADDRESS).
func BindingRequest(conn *net.UDPConn, serverAddr string) (*BindingResult, error) {
	srv, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve stun server %s: %w", serverAddr, err)
	}

	txID := make([]byte, 12)
	if _, err := rand.Read(txID); err != nil {
		return nil, err
	}

	req := buildBindingRequest(txID)
	if err := conn.SetWriteDeadline(time.Now().Add(stunDialTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.WriteToUDP(req, srv); err != nil {
		return nil, fmt.Errorf("send stun request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(stunDialTimeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("read stun response: %w", err)
	}
	// Clear the deadline so the connection can be reused.
	_ = conn.SetReadDeadline(time.Time{})

	publicAddr, err := parseBindingResponse(buf[:n], txID)
	if err != nil {
		return nil, err
	}

	return &BindingResult{PublicAddr: publicAddr, ServerAddr: serverAddr}, nil
}

// buildBindingRequest constructs a minimal STUN Binding Request.
func buildBindingRequest(txID []byte) []byte {
	// STUN header: type(2) + length(2) + magic(4) + txID(12) = 20 bytes
	buf := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(buf[0:], stunMsgTypeBindingRequest)
	binary.BigEndian.PutUint16(buf[2:], 0) // message length = 0 (no attributes)
	binary.BigEndian.PutUint32(buf[4:], stunMagicCookie)
	copy(buf[8:], txID)
	return buf
}

// parseBindingResponse parses a STUN Binding Response and returns the mapped address.
func parseBindingResponse(buf, txID []byte) (*net.UDPAddr, error) {
	if len(buf) < stunHeaderSize {
		return nil, fmt.Errorf("stun response too short")
	}

	msgType := binary.BigEndian.Uint16(buf[0:])
	if msgType != stunMsgTypeBindingResponse {
		return nil, fmt.Errorf("unexpected stun msg type 0x%04x", msgType)
	}

	// Verify transaction ID.
	if string(buf[8:20]) != string(txID) {
		return nil, fmt.Errorf("stun txID mismatch")
	}

	msgLen := int(binary.BigEndian.Uint16(buf[2:]))
	if len(buf) < stunHeaderSize+msgLen {
		return nil, fmt.Errorf("stun response truncated")
	}

	// Parse attributes.
	pos := stunHeaderSize
	end := stunHeaderSize + msgLen
	var mappedAddr, xorMappedAddr *net.UDPAddr

	for pos+4 <= end {
		attrType := binary.BigEndian.Uint16(buf[pos:])
		attrLen := int(binary.BigEndian.Uint16(buf[pos+2:]))
		pos += 4
		if pos+attrLen > end {
			break
		}
		attrData := buf[pos : pos+attrLen]

		switch attrType {
		case stunAttrMappedAddress:
			addr, err := parseMappedAddress(attrData)
			if err == nil {
				mappedAddr = addr
			}
		case stunAttrXORMappedAddress:
			addr, err := parseXORMappedAddress(attrData, txID)
			if err == nil {
				xorMappedAddr = addr
			}
		}
		// Pad to 4-byte boundary.
		pos += (attrLen + 3) &^ 3
	}

	if xorMappedAddr != nil {
		return xorMappedAddr, nil
	}
	if mappedAddr != nil {
		return mappedAddr, nil
	}
	return nil, fmt.Errorf("no mapped address in stun response")
}

// parseMappedAddress parses a STUN MAPPED-ADDRESS attribute.
func parseMappedAddress(b []byte) (*net.UDPAddr, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("mapped address too short")
	}
	family := b[1]
	port := int(binary.BigEndian.Uint16(b[2:]))
	switch family {
	case stunAddrFamilyIPv4:
		if len(b) < 8 {
			return nil, fmt.Errorf("ipv4 attr too short")
		}
		ip := net.IP(b[4:8])
		return &net.UDPAddr{IP: ip, Port: port}, nil
	case stunAddrFamilyIPv6:
		if len(b) < 20 {
			return nil, fmt.Errorf("ipv6 attr too short")
		}
		ip := net.IP(b[4:20])
		return &net.UDPAddr{IP: ip, Port: port}, nil
	default:
		return nil, fmt.Errorf("unknown address family %d", family)
	}
}

// parseXORMappedAddress parses a STUN XOR-MAPPED-ADDRESS attribute.
// txID is the 12-byte transaction ID from the request, needed for IPv6 XOR decoding.
func parseXORMappedAddress(b, txID []byte) (*net.UDPAddr, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("xor mapped address too short")
	}
	family := b[1]
	// XOR port with high 16 bits of magic cookie.
	xorPort := binary.BigEndian.Uint16(b[2:]) ^ uint16(stunMagicCookie>>16)
	port := int(xorPort)

	switch family {
	case stunAddrFamilyIPv4:
		if len(b) < 8 {
			return nil, fmt.Errorf("xor ipv4 too short")
		}
		xorIP := make([]byte, 4)
		magicBytes := [4]byte{0x21, 0x12, 0xA4, 0x42}
		for i := 0; i < 4; i++ {
			xorIP[i] = b[4+i] ^ magicBytes[i]
		}
		return &net.UDPAddr{IP: net.IP(xorIP), Port: port}, nil
	case stunAddrFamilyIPv6:
		if len(b) < 20 {
			return nil, fmt.Errorf("xor ipv6 too short")
		}
		if len(txID) < 12 {
			return nil, fmt.Errorf("xor ipv6: txID too short")
		}
		// RFC 5389 §15.2: XOR the IP with magic cookie (4 bytes) + transaction ID (12 bytes).
		xorIP := make([]byte, 16)
		xorKey := make([]byte, 16)
		binary.BigEndian.PutUint32(xorKey[0:], stunMagicCookie)
		copy(xorKey[4:], txID)
		for i := 0; i < 16; i++ {
			xorIP[i] = b[4+i] ^ xorKey[i]
		}
		return &net.UDPAddr{IP: net.IP(xorIP), Port: port}, nil
	default:
		return nil, fmt.Errorf("unknown address family %d in xor mapped address", family)
	}
}
