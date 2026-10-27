package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

func TestAESFileRoundTripAndStandardLibrary(t *testing.T) {
	if AESFileKeySize != 32 {
		t.Fatalf("master key size: got %d, want 32", AESFileKeySize)
	}
	key := aesFileTestKey()
	for _, size := range []int{0, 1, 15, 16, 17, 64*1024 + 7} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			for i := range plaintext {
				plaintext[i] = byte(i*37 + i/256)
			}
			original := bytes.Clone(plaintext)
			encrypted, err := EncryptAESFile(plaintext, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, original) {
				t.Fatal("encryption modified the input")
			}
			wantSize := 4 + 16 + (size/16+1)*16 + sha256.Size
			if len(encrypted) != wantSize || string(encrypted[:4]) != "AES1" {
				t.Fatalf("invalid envelope: length %d, want %d; magic %q", len(encrypted), wantSize, encrypted[:4])
			}

			originalEncrypted := bytes.Clone(encrypted)
			got, err := DecryptAESFile(encrypted, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("round trip changed plaintext")
			}
			if !bytes.Equal(encrypted, originalEncrypted) {
				t.Fatal("decryption modified the input")
			}

			// Derive keys, verify the tag, and decrypt without implementation helpers.
			block, macKey := aesFileOracleKeys(t, key)
			bodyEnd := len(encrypted) - sha256.Size
			mac := hmac.New(sha256.New, macKey)
			mac.Write(encrypted[:bodyEnd])
			if !hmac.Equal(mac.Sum(nil), encrypted[bodyEnd:]) {
				t.Fatal("standard-library HMAC verification failed")
			}
			padded := make([]byte, bodyEnd-20)
			cipher.NewCBCDecrypter(block, encrypted[4:20]).CryptBlocks(padded, encrypted[20:bodyEnd])
			padding := 16 - size%16
			want := append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(padding)}, padding)...)
			if !bytes.Equal(padded, want) {
				t.Fatal("standard-library CBC decryption or PKCS7 padding mismatch")
			}
		})
	}
}

func TestAESFileDecryptStandardLibraryEnvelopes(t *testing.T) {
	key := aesFileTestKey()
	// Exercise every valid padding length, including a full padding block.
	for size := 0; size < 32; size++ {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			plaintext := bytes.Repeat([]byte{0xa5}, size)
			padding := 16 - size%16
			padded := append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(padding)}, padding)...)
			encrypted := aesFileOracleEnvelope(t, padded, key)
			got, err := DecryptAESFile(encrypted, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("could not decrypt independent standard-library envelope")
			}
		})
	}
}

func TestAESFileRandomIV(t *testing.T) {
	key := aesFileTestKey()
	plaintext := []byte("the same plaintext and key")
	first, err := EncryptAESFile(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptAESFile(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[4:20], second[4:20]) {
		t.Fatal("repeated IV")
	}
	if bytes.Equal(first[20:len(first)-32], second[20:len(second)-32]) {
		t.Fatal("repeated ciphertext despite distinct IVs")
	}
	if bytes.Equal(first[len(first)-32:], second[len(second)-32:]) {
		t.Fatal("repeated MAC despite distinct IVs")
	}
}

func TestAESFileWrongKeyAndCorruption(t *testing.T) {
	key := aesFileTestKey()
	encrypted, err := EncryptAESFile(bytes.Repeat([]byte{0x80}, 33), key)
	if err != nil {
		t.Fatal(err)
	}
	// Both halves of the master key must affect authentication.
	for _, offset := range []int{0, 16, 31} {
		wrongKey := key
		wrongKey[offset] ^= 1
		got, err := DecryptAESFile(encrypted, wrongKey)
		if got != nil || !errors.Is(err, errAESFileAuthentication) {
			t.Fatalf("wrong key byte %d: got %x, error %v", offset, got, err)
		}
	}

	// Cover every byte of the magic, IV, ciphertext, and tag.
	for offset := range encrypted {
		t.Run(fmt.Sprintf("byte_%d", offset), func(t *testing.T) {
			corrupted := bytes.Clone(encrypted)
			corrupted[offset] ^= 1
			wantErr := errAESFileAuthentication
			if offset < 4 {
				wantErr = errAESFileFormat
			}
			got, err := DecryptAESFile(corrupted, key)
			if got != nil || !errors.Is(err, wantErr) {
				t.Fatalf("got %x, error %v; want %v", got, err, wantErr)
			}
		})
	}
}

func TestAESFileMalformedEnvelopes(t *testing.T) {
	key := aesFileTestKey()
	encrypted, err := EncryptAESFile(bytes.Repeat([]byte{0xff}, 17), key)
	if err != nil {
		t.Fatal(err)
	}
	for size := 0; size < len(encrypted); size++ {
		t.Run(fmt.Sprintf("truncated_%d", size), func(t *testing.T) {
			if got, err := DecryptAESFile(encrypted[:size], key); got != nil || err == nil {
				t.Fatalf("got %x, error %v", got, err)
			}
		})
	}

	for _, extra := range []int{1, 15, 16, 32} {
		malformed := append(bytes.Clone(encrypted), make([]byte, extra)...)
		if got, err := DecryptAESFile(malformed, key); got != nil || err == nil {
			t.Fatalf("appended %d bytes: got %x, error %v", extra, got, err)
		}
	}

	// Even a correctly authenticated envelope needs at least one whole block.
	empty := aesFileOracleEnvelope(t, nil, key)
	if got, err := DecryptAESFile(empty, key); got != nil || !errors.Is(err, errAESFileFormat) {
		t.Fatalf("empty ciphertext: got %x, error %v", got, err)
	}
	for _, size := range []int{1, 15, 17, 31} {
		malformed := append(bytes.Clone(empty[:20]), make([]byte, size)...)
		malformed = aesFileOracleSign(t, malformed, key)
		if got, err := DecryptAESFile(malformed, key); got != nil || !errors.Is(err, errAESFileFormat) {
			t.Fatalf("ciphertext size %d: got %x, error %v", size, got, err)
		}
	}
}

func TestAESFileRejectsAuthenticatedInvalidPadding(t *testing.T) {
	key := aesFileTestKey()
	cases := map[string][]byte{
		"zero":      bytes.Repeat([]byte{0}, 16),
		"too_large": bytes.Repeat([]byte{17}, 16),
		"max_byte":  bytes.Repeat([]byte{255}, 16),
		"mismatch":  append(bytes.Repeat([]byte{1}, 15), 2),
	}
	for offset := 0; offset < 15; offset++ {
		padded := bytes.Repeat([]byte{16}, 16)
		padded[offset] = 15
		cases[fmt.Sprintf("full_block_mismatch_%d", offset)] = padded
	}
	for name, padded := range cases {
		t.Run(name, func(t *testing.T) {
			encrypted := aesFileOracleEnvelope(t, padded, key)
			if got, err := DecryptAESFile(encrypted, key); got != nil || !errors.Is(err, errAESFilePadding) {
				t.Fatalf("authenticated invalid padding: got %x, error %v", got, err)
			}
			// Invalid MAC must take precedence over the known invalid padding.
			encrypted[len(encrypted)-1] ^= 1
			if got, err := DecryptAESFile(encrypted, key); got != nil || !errors.Is(err, errAESFileAuthentication) {
				t.Fatalf("unauthenticated invalid padding: got %x, error %v", got, err)
			}
		})
	}
}

func aesFileTestKey() [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	return key
}

// Oracle helpers deliberately use literal format/derivation values and only
// standard-library crypto, independently of the file implementation helpers.
func aesFileOracleKeys(t *testing.T, key [32]byte) (cipher.Block, []byte) {
	t.Helper()
	encMAC := hmac.New(sha256.New, key[:])
	encMAC.Write([]byte("AES1/encryption"))
	block, err := aes.NewCipher(encMAC.Sum(nil)[:16])
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("AES1/authentication"))
	return block, mac.Sum(nil)
}

func aesFileOracleSign(t *testing.T, body []byte, key [32]byte) []byte {
	t.Helper()
	_, macKey := aesFileOracleKeys(t, key)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(body)
	return append(body, mac.Sum(nil)...)
}

func aesFileOracleEnvelope(t *testing.T, padded []byte, key [32]byte) []byte {
	t.Helper()
	block, _ := aesFileOracleKeys(t, key)
	body := make([]byte, 20+len(padded))
	copy(body, "AES1")
	copy(body[4:20], []byte("test-only-IV-123"))
	cipher.NewCBCEncrypter(block, body[4:20]).CryptBlocks(body[20:], padded)
	return aesFileOracleSign(t, body, key)
}
