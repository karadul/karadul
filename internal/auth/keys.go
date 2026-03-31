package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PreAuthKey is a one-time or reusable key that grants a node permission to join.
type PreAuthKey struct {
	ID        string    `json:"id"`
	Secret    string    `json:"secret"`
	Ephemeral bool      `json:"ephemeral"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	Used      bool      `json:"used"`
	UsedAt    time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// GeneratePreAuthKey creates a new random pre-auth key.
func GeneratePreAuthKey(ephemeral bool, ttl time.Duration) (*PreAuthKey, error) {
	idBytes := make([]byte, 8)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}

	k := &PreAuthKey{
		ID:        hex.EncodeToString(idBytes),
		Secret:    hex.EncodeToString(secretBytes),
		Ephemeral: ephemeral,
		CreatedAt: time.Now(),
	}
	if ttl > 0 {
		k.ExpiresAt = time.Now().Add(ttl)
	}
	return k, nil
}

// IsValid reports whether the key may be used right now.
func (k *PreAuthKey) IsValid() bool {
	if k.Ephemeral && k.Used {
		return false
	}
	if !k.ExpiresAt.IsZero() && time.Now().After(k.ExpiresAt) {
		return false
	}
	return true
}

// KeyStore is a simple file-backed pre-auth key store.
type KeyStore struct {
	dir string
}

// NewKeyStore creates a KeyStore rooted at dir.
func NewKeyStore(dir string) (*KeyStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &KeyStore{dir: dir}, nil
}

// Save writes a key to its file.
func (ks *KeyStore) Save(k *PreAuthKey) error {
	path := filepath.Join(ks.dir, k.ID+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeJSON(f, k)
}

// Load reads a key by ID.
func (ks *KeyStore) Load(id string) (*PreAuthKey, error) {
	path := filepath.Join(ks.dir, id+".json")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}
	defer f.Close()
	var k PreAuthKey
	if err := readJSON(f, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

// FindBySecret returns the key whose Secret field matches.
// It reads each key file's JSON directly without full deserialization overhead.
func (ks *KeyStore) FindBySecret(secret string) (*PreAuthKey, error) {
	entries, err := os.ReadDir(ks.dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) <= 5 || name[len(name)-5:] != ".json" {
			continue
		}
		id := name[:len(name)-5]
		k, err := ks.Load(id)
		if err != nil {
			continue
		}
		if k.Secret == secret {
			return k, nil
		}
	}
	return nil, fmt.Errorf("key not found")
}

// List returns all stored keys.
func (ks *KeyStore) List() ([]*PreAuthKey, error) {
	entries, err := os.ReadDir(ks.dir)
	if err != nil {
		return nil, err
	}
	var keys []*PreAuthKey
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) <= 5 || name[len(name)-5:] != ".json" {
			continue
		}
		id := name[:len(name)-5]
		k, err := ks.Load(id)
		if err != nil {
			continue
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Delete removes a key.
func (ks *KeyStore) Delete(id string) error {
	return os.Remove(filepath.Join(ks.dir, id+".json"))
}
