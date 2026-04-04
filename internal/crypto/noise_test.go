package crypto

import (
	"bytes"
	"testing"
)

func TestNoiseIKHandshake(t *testing.T) {
	// Generate key pairs for initiator and responder.
	ikp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rkp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Initiator knows responder's public key upfront (IK pattern).
	initiator, err := InitiatorHandshake(ikp, rkp.Public)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := ResponderHandshake(rkp)
	if err != nil {
		t.Fatal(err)
	}

	// Message 1: initiator → responder.
	msg1, err := initiator.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if len(msg1) != 96 {
		t.Fatalf("msg1 length: got %d, want 96", len(msg1))
	}

	if err := responder.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}

	// Responder should now know initiator's static key.
	if responder.RemoteStaticKey() != ikp.Public {
		t.Fatal("responder has wrong initiator static key")
	}

	// Message 2: responder → initiator.
	msg2, err := responder.WriteMessage2()
	if err != nil {
		t.Fatalf("WriteMessage2: %v", err)
	}
	if len(msg2) != 48 {
		t.Fatalf("msg2 length: got %d, want 48", len(msg2))
	}

	if err := initiator.ReadMessage2(msg2); err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}

	// Both sides derive transport keys.
	iSend, iRecv, err := initiator.TransportKeys()
	if err != nil {
		t.Fatal(err)
	}
	rSend, rRecv, err := responder.TransportKeys()
	if err != nil {
		t.Fatal(err)
	}

	// Initiator's send key == Responder's recv key and vice versa.
	if iSend != rRecv {
		t.Fatalf("initiator send key != responder recv key")
	}
	if iRecv != rSend {
		t.Fatalf("initiator recv key != responder send key")
	}

	// Verify we can encrypt and decrypt with the derived keys.
	plaintext := []byte("mesh VPN test packet")
	ct, err := EncryptAEAD(iSend, 0, plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptAEAD(rRecv, 0, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypted: %q, want %q", pt, plaintext)
	}
}

func TestNoiseHandshakeWrongRemoteKey(t *testing.T) {
	// Initiator uses wrong responder key → ReadMessage1 should fail.
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()
	wrongKP, _ := GenerateKeyPair()

	initiator, _ := InitiatorHandshake(ikp, wrongKP.Public) // wrong key!
	responder, _ := ResponderHandshake(rkp)

	msg1, _ := initiator.WriteMessage1()
	if err := responder.ReadMessage1(msg1); err == nil {
		t.Fatal("ReadMessage1 with wrong responder key should fail")
	}
}

// TestWriteMessage1_WrongRole verifies WriteMessage1 fails when called on a responder.
func TestWriteMessage1_WrongRole(t *testing.T) {
	rkp, _ := GenerateKeyPair()
	responder, _ := ResponderHandshake(rkp)
	if _, err := responder.WriteMessage1(); err == nil {
		t.Fatal("WriteMessage1 should fail on a responder")
	}
}

// TestWriteMessage1_WrongState verifies WriteMessage1 fails when nMsg != 0.
func TestWriteMessage1_WrongState(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()
	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	// Advance state past 0.
	initiator.nMsg = 1
	if _, err := initiator.WriteMessage1(); err == nil {
		t.Fatal("WriteMessage1 should fail when nMsg != 0")
	}
}

// TestReadMessage1_WrongRole verifies ReadMessage1 fails when called on an initiator.
func TestReadMessage1_WrongRole(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()
	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	dummy := make([]byte, 96)
	if err := initiator.ReadMessage1(dummy); err == nil {
		t.Fatal("ReadMessage1 should fail on an initiator")
	}
}

// TestReadMessage1_WrongState verifies ReadMessage1 fails when nMsg != 0.
func TestReadMessage1_WrongState(t *testing.T) {
	rkp, _ := GenerateKeyPair()
	responder, _ := ResponderHandshake(rkp)
	responder.nMsg = 1 // already advanced
	dummy := make([]byte, 96)
	if err := responder.ReadMessage1(dummy); err == nil {
		t.Fatal("ReadMessage1 should fail when nMsg != 0")
	}
}

// TestReadMessage1_TooShort verifies ReadMessage1 fails on a short message.
func TestReadMessage1_TooShort(t *testing.T) {
	rkp, _ := GenerateKeyPair()
	responder, _ := ResponderHandshake(rkp)
	if err := responder.ReadMessage1(make([]byte, 10)); err == nil {
		t.Fatal("ReadMessage1 should fail for message shorter than 96 bytes")
	}
}

// TestWriteMessage2_WrongRole verifies WriteMessage2 fails when called on an initiator.
func TestWriteMessage2_WrongRole(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()
	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	if _, err := initiator.WriteMessage2(); err == nil {
		t.Fatal("WriteMessage2 should fail on an initiator")
	}
}

// TestWriteMessage2_WrongState verifies WriteMessage2 fails when nMsg != 1.
func TestWriteMessage2_WrongState(t *testing.T) {
	rkp, _ := GenerateKeyPair()
	responder, _ := ResponderHandshake(rkp)
	// nMsg is 0 (ReadMessage1 hasn't been called yet)
	if _, err := responder.WriteMessage2(); err == nil {
		t.Fatal("WriteMessage2 should fail when nMsg != 1")
	}
}

// TestReadMessage2_WrongRole verifies ReadMessage2 fails when called on a responder.
func TestReadMessage2_WrongRole(t *testing.T) {
	rkp, _ := GenerateKeyPair()
	responder, _ := ResponderHandshake(rkp)
	responder.nMsg = 1
	if err := responder.ReadMessage2(make([]byte, 48)); err == nil {
		t.Fatal("ReadMessage2 should fail on a responder")
	}
}

// TestReadMessage2_WrongState verifies ReadMessage2 fails when nMsg != 1.
func TestReadMessage2_WrongState(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()
	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	// nMsg is 0, not 1
	if err := initiator.ReadMessage2(make([]byte, 48)); err == nil {
		t.Fatal("ReadMessage2 should fail when nMsg != 1")
	}
}

// TestReadMessage2_TooShort verifies ReadMessage2 fails on a short message.
func TestReadMessage2_TooShort(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()
	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	initiator.nMsg = 1
	if err := initiator.ReadMessage2(make([]byte, 10)); err == nil {
		t.Fatal("ReadMessage2 should fail for message shorter than 48 bytes")
	}
}

// TestReadMessage2_AuthFailure verifies ReadMessage2 fails when the payload auth tag is wrong.
func TestReadMessage2_AuthFailure(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()

	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	responder, _ := ResponderHandshake(rkp)

	msg1, _ := initiator.WriteMessage1()
	_ = responder.ReadMessage1(msg1)
	msg2, _ := responder.WriteMessage2()

	// Corrupt the auth tag (last 16 bytes of msg2).
	for i := 32; i < 48; i++ {
		msg2[i] ^= 0xFF
	}
	if err := initiator.ReadMessage2(msg2); err == nil {
		t.Fatal("ReadMessage2 should fail with corrupted auth tag")
	}
}

// TestTransportKeys_Incomplete verifies TransportKeys fails before the handshake finishes.
func TestTransportKeys_Incomplete(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()
	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	// nMsg == 0, handshake not done
	if _, _, err := initiator.TransportKeys(); err == nil {
		t.Fatal("TransportKeys should fail before handshake is complete")
	}
}

// TestTransportKeys_Responder verifies that the responder's TransportKeys
// returns keys in the opposite order from the initiator's.
func TestTransportKeys_Responder(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()

	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	responder, _ := ResponderHandshake(rkp)

	msg1, _ := initiator.WriteMessage1()
	_ = responder.ReadMessage1(msg1)
	msg2, _ := responder.WriteMessage2()
	_ = initiator.ReadMessage2(msg2)

	iSend, iRecv, _ := initiator.TransportKeys()
	rSend, rRecv, _ := responder.TransportKeys()

	// Responder send == Initiator recv, Responder recv == Initiator send.
	if rSend != iRecv {
		t.Fatal("responder send key should equal initiator recv key")
	}
	if rRecv != iSend {
		t.Fatal("responder recv key should equal initiator send key")
	}
}

// TestReadMessage1_CorruptedEncryptedStatic verifies ReadMessage1 fails when
// the encrypted static key section (bytes 32-80) is corrupted.
func TestReadMessage1_CorruptedEncryptedStatic(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()

	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	responder, _ := ResponderHandshake(rkp)

	msg1, _ := initiator.WriteMessage1()

	// Corrupt a byte in the encrypted static key section (bytes 32-79).
	msg1[40] ^= 0xFF

	if err := responder.ReadMessage1(msg1); err == nil {
		t.Fatal("ReadMessage1 should fail with corrupted encrypted static key")
	}
}

// TestReadMessage1_CorruptedPayloadTag verifies ReadMessage1 fails when the
// payload auth tag (bytes 80-95) is corrupted.
func TestReadMessage1_CorruptedPayloadTag(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()

	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	responder, _ := ResponderHandshake(rkp)

	msg1, _ := initiator.WriteMessage1()

	// Corrupt the payload auth tag (bytes 80-95).
	msg1[88] ^= 0xFF

	if err := responder.ReadMessage1(msg1); err == nil {
		t.Fatal("ReadMessage1 should fail with corrupted payload tag")
	}
}

// TestReadMessage1_CorruptedEphemeralKey verifies ReadMessage1 fails when the
// ephemeral public key (bytes 0-31) is corrupted, causing ECDH to derive wrong keys.
func TestReadMessage1_CorruptedEphemeralKey(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()

	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	responder, _ := ResponderHandshake(rkp)

	msg1, _ := initiator.WriteMessage1()

	// Corrupt the ephemeral key (first 32 bytes).
	msg1[0] ^= 0xFF

	if err := responder.ReadMessage1(msg1); err == nil {
		t.Fatal("ReadMessage1 should fail with corrupted ephemeral key")
	}
}

// TestReadMessage2_CorruptedEphemeralKey verifies ReadMessage2 fails when the
// ephemeral public key (bytes 0-31) is corrupted.
func TestReadMessage2_CorruptedEphemeralKey(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()

	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	responder, _ := ResponderHandshake(rkp)

	msg1, _ := initiator.WriteMessage1()
	_ = responder.ReadMessage1(msg1)
	msg2, _ := responder.WriteMessage2()

	// Corrupt the ephemeral key in msg2.
	msg2[0] ^= 0xFF

	if err := initiator.ReadMessage2(msg2); err == nil {
		t.Fatal("ReadMessage2 should fail with corrupted ephemeral key")
	}
}

// TestTwoHandshakesProduceDifferentKeys verifies that two consecutive handshakes
// between the same peers produce different transport keys (due to new ephemerals).
func TestTwoHandshakesProduceDifferentKeys(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()

	doHandshake := func() (iSend, iRecv [32]byte) {
		initiator, _ := InitiatorHandshake(ikp, rkp.Public)
		responder, _ := ResponderHandshake(rkp)
		msg1, _ := initiator.WriteMessage1()
		_ = responder.ReadMessage1(msg1)
		msg2, _ := responder.WriteMessage2()
		_ = initiator.ReadMessage2(msg2)
		iSend, iRecv, _ = initiator.TransportKeys()
		return
	}

	s1, r1 := doHandshake()
	s2, r2 := doHandshake()

	if s1 == s2 {
		t.Error("two handshakes should produce different send keys")
	}
	if r1 == r2 {
		t.Error("two handshakes should produce different recv keys")
	}
}

// TestRemoteStaticKey_Initiator verifies that the initiator's RemoteStaticKey
// returns the responder's public key that was passed to InitiatorHandshake.
func TestRemoteStaticKey_Initiator(t *testing.T) {
	ikp, _ := GenerateKeyPair()
	rkp, _ := GenerateKeyPair()

	initiator, _ := InitiatorHandshake(ikp, rkp.Public)
	remote := initiator.RemoteStaticKey()
	if remote != rkp.Public {
		t.Error("initiator should have responder's static key")
	}
}
