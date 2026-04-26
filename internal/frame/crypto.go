package frame

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Crypto wraps an AES-256-GCM AEAD with the relay-tunnel envelope format:
//
//	nonce (12 bytes) || ciphertext+tag (Seal output, tag is the trailing 16 bytes)
type Crypto struct {
	aead cipher.AEAD
}

// NewCryptoFromHexKey parses a 64-char hex string into a 32-byte AES-256 key
// and constructs a Crypto. The same key must be configured on both client and DO server.
func NewCryptoFromHexKey(hexKey string) (*Crypto, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return &Crypto{aead: gcm}, nil
}

// Seal encrypts plaintext and returns nonce||ciphertext (tag appended by GCM).
func (c *Crypto) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce read: %w", err)
	}
	ct := c.aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open inverts Seal. Returns an error on auth-tag failure (tampered ciphertext,
// nonce, or tag, or wrong key).
func (c *Crypto) Open(envelope []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(envelope) < ns+c.aead.Overhead() {
		return nil, errors.New("crypto: envelope too short")
	}
	nonce := envelope[:ns]
	ct := envelope[ns:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	return pt, nil
}

// EncodeBatch packs zero or more frames into a base64-encoded HTTP body:
//
//	[u16 frame_count][ for each frame: u32 envelope_len || envelope ]
//
// The whole concatenation is then base64-encoded so it survives Apps Script's
// ContentService text round-trip.
func EncodeBatch(c *Crypto, frames []*Frame) ([]byte, error) {
	if len(frames) > 0xFFFF {
		return nil, fmt.Errorf("batch: too many frames: %d", len(frames))
	}
	// Reserve count header + per-frame length prefixes; frame envelopes are appended.
	buf := make([]byte, 2, 2+len(frames)*512)
	binary.BigEndian.PutUint16(buf, uint16(len(frames)))
	for _, f := range frames {
		raw, err := f.Marshal()
		if err != nil {
			return nil, fmt.Errorf("batch: marshal frame: %w", err)
		}
		env, err := c.Seal(raw)
		if err != nil {
			return nil, fmt.Errorf("batch: seal frame: %w", err)
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(env)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, env...)
	}
	enc := base64.StdEncoding.EncodeToString(buf)
	return []byte(enc), nil
}

// DecodeBatch is the inverse of EncodeBatch. Frames whose envelope fails
// AES-GCM auth are dropped silently (returned in the error log only).
func DecodeBatch(c *Crypto, body []byte) ([]*Frame, error) {
	if len(body) == 0 {
		return nil, nil
	}
	// Trim whitespace — Apps Script's getContentText() can append a trailing
	// newline which breaks strict base64 decoding.
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("batch: base64 decode: %w", err)
	}
	if len(raw) < 2 {
		return nil, errors.New("batch: short header")
	}
	count := int(binary.BigEndian.Uint16(raw[:2]))
	off := 2
	frames := make([]*Frame, 0, count)
	for i := 0; i < count; i++ {
		if len(raw) < off+4 {
			return nil, errors.New("batch: short frame length")
		}
		flen := int(binary.BigEndian.Uint32(raw[off:]))
		off += 4
		if len(raw) < off+flen {
			return nil, errors.New("batch: short frame body")
		}
		env := raw[off : off+flen]
		off += flen
		pt, err := c.Open(env)
		if err != nil {
			// Silent drop on auth failure — this is the only authentication.
			continue
		}
		f, _, err := Unmarshal(pt)
		if err != nil {
			continue
		}
		frames = append(frames, f)
	}
	return frames, nil
}
