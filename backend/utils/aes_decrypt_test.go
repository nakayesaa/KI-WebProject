package utils

import (
	"crypto/aes"
	"encoding/hex"
	"math/rand"
	"testing"
)

func TestAesDecrypt128KnownVectors(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		ciphertext string
		plaintext  string
	}{
		{
			name:       "FIPS 197 AES-128",
			key:        "000102030405060708090a0b0c0d0e0f",
			ciphertext: "69c4e0d86a7b0430d8cdb78070b4c55a",
			plaintext:  "00112233445566778899aabbccddeeff",
		},
		{
			name:       "zero key and plaintext",
			key:        "00000000000000000000000000000000",
			ciphertext: "66e94bd4ef8a2c3b884cfa59ca342b2e",
			plaintext:  "00000000000000000000000000000000",
		},
		{
			name:       "NIST SP 800-38A first block",
			key:        "2b7e151628aed2a6abf7158809cf4f3c",
			ciphertext: "3ad77bb40d7a3660a89ecaf32466ef97",
			plaintext:  "6bc1bee22e409f96e93d7e117393172a",
		},
		{
			name:       "NIST SP 800-38A second block",
			key:        "2b7e151628aed2a6abf7158809cf4f3c",
			ciphertext: "f5d3d58503b9699de785895a96fdbaaf",
			plaintext:  "ae2d8a571e03ac9c9eb76fac45af8e51",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := decodeAESBlock(t, tt.key)
			ciphertext := decodeAESBlock(t, tt.ciphertext)
			plaintext := decodeAESBlock(t, tt.plaintext)

			if got := AesDecrypt128(ciphertext, key); got != plaintext {
				t.Fatalf("decryption: got %x, want %x", got, plaintext)
			}
			if got := AesEncrypt128(plaintext, key); got != ciphertext {
				t.Fatalf("encryption: got %x, want %x", got, ciphertext)
			}
		})
	}
}

func TestAESInverseTransforms(t *testing.T) {
	sbox := GenerateSBox()
	inverseSBox := GenerateInverseSBox(sbox)

	for i := range 256 {
		if got := inverseSBox[sbox[i]]; got != byte(i) {
			t.Fatalf("inverse S-box: input %02x, got %02x", i, got)
		}
	}

	tests := []struct {
		name    string
		forward func(*State)
		inverse func(*State)
	}{
		{
			name: "SubBytes",
			forward: func(state *State) {
				SubBytes(state, &sbox)
			},
			inverse: func(state *State) {
				InvSubBytes(state, &inverseSBox)
			},
		},
		{name: "ShiftRow", forward: ShiftRow, inverse: InvShiftRow},
		{name: "MixColumns", forward: MixColumns, inverse: InvMixColumns},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cover every byte value in every state position across 256 inputs.
			for offset := range 256 {
				var block [16]byte
				for i := range block {
					block[i] = byte(offset + i)
				}
				original := BytesToState(block)
				state := original
				tt.forward(&state)
				tt.inverse(&state)

				if state != original {
					t.Fatalf("offset %d: got %x, want %x", offset, state, original)
				}
			}
		})
	}
}

func TestAesDecrypt128AgainstStandardLibrary(t *testing.T) {
	// A fixed seed makes failures reproducible; these are not production keys.
	rng := rand.New(rand.NewSource(1))

	for i := range 32 {
		var key, plaintext, ciphertext [16]byte
		for j := range key {
			key[j] = byte(rng.Intn(256))
			plaintext[j] = byte(rng.Intn(256))
			ciphertext[j] = byte(rng.Intn(256))
		}

		block, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}

		var expected [16]byte
		block.Decrypt(expected[:], ciphertext[:])
		if got := AesDecrypt128(ciphertext, key); got != expected {
			t.Fatalf("case %d: got %x, want %x", i, got, expected)
		}

		block.Encrypt(ciphertext[:], plaintext[:])
		if got := AesDecrypt128(ciphertext, key); got != plaintext {
			t.Fatalf("case %d, standard-library ciphertext: got %x, want %x", i, got, plaintext)
		}

		encrypted := AesEncrypt128(plaintext, key)
		if got := AesDecrypt128(encrypted, key); got != plaintext {
			t.Fatalf("case %d, round trip: got %x, want %x", i, got, plaintext)
		}
	}
}

func decodeAESBlock(t *testing.T, value string) [16]byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 16 {
		t.Fatalf("expected 16-byte block, got %d bytes", len(decoded))
	}

	var block [16]byte
	copy(block[:], decoded)
	return block
}
