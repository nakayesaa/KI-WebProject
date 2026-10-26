package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// AESFileKeySize is the size in bytes of the master key, not a password.
const AESFileKeySize = 32

const (
	aesFileMagic      = "AES1"
	aesFileBlockSize  = 16
	aesFileHeaderSize = len(aesFileMagic) + aesFileBlockSize
	aesFileEncLabel   = "AES1/encryption"
	aesFileMACLabel   = "AES1/authentication"
)

var (
	errAESFileFormat         = errors.New("AES file: invalid envelope")
	errAESFileAuthentication = errors.New("AES file: authentication failed")
	errAESFilePadding        = errors.New("AES file: invalid PKCS7 padding")
)

// EncryptAESFile returns magic "AES1" || random 16-byte IV || AES-128-CBC
// ciphertext (PKCS7 padded) || HMAC-SHA256(magic || IV || ciphertext).
// The encryption key is the first 16 bytes of HMAC-SHA256(key, "AES1/encryption");
// the MAC key is HMAC-SHA256(key, "AES1/authentication").
// This uses educational, non-constant-time handmade AES, not production crypto.
func EncryptAESFile(plaintext []byte, key [32]byte) ([]byte, error) {
	padding := aesFileBlockSize - len(plaintext)%aesFileBlockSize
	if len(plaintext) > int(^uint(0)>>1)-aesFileHeaderSize-sha256.Size-padding {
		return nil, errors.New("AES file: plaintext too large")
	}
	bodyEnd := aesFileHeaderSize + len(plaintext) + padding
	encrypted := make([]byte, bodyEnd+sha256.Size)
	copy(encrypted, aesFileMagic)
	iv := encrypted[len(aesFileMagic):aesFileHeaderSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("AES file: generate IV: %w", err)
	}

	encKey, macKey := deriveAESFileKeys(key)
	prepared := prepareAES128(encKey)
	ciphertext := encrypted[aesFileHeaderSize:bodyEnd]
	copy(ciphertext, plaintext)
	for i := len(plaintext); i < len(ciphertext); i++ {
		ciphertext[i] = byte(padding)
	}
	previous := iv
	for offset := 0; offset < len(ciphertext); offset += aesFileBlockSize {
		block := [aesFileBlockSize]byte(ciphertext[offset : offset+aesFileBlockSize])
		for i := range block {
			block[i] ^= previous[i]
		}
		block = prepared.encrypt(block)
		copy(ciphertext[offset:], block[:])
		previous = ciphertext[offset : offset+aesFileBlockSize]
	}

	mac := hmac.New(sha256.New, macKey[:])
	mac.Write(encrypted[:bodyEnd])
	copy(encrypted[bodyEnd:], mac.Sum(nil))
	return encrypted, nil
}

// DecryptAESFile validates the envelope and authenticates it before performing
// any AES decryption or padding checks. Errors never return partial plaintext.
// The handmade AES is educational and is not constant-time.
func DecryptAESFile(encrypted []byte, key [32]byte) ([]byte, error) {
	if len(encrypted) < aesFileHeaderSize+aesFileBlockSize+sha256.Size {
		return nil, errAESFileFormat
	}
	bodyEnd := len(encrypted) - sha256.Size
	if string(encrypted[:len(aesFileMagic)]) != aesFileMagic ||
		(bodyEnd-aesFileHeaderSize)%aesFileBlockSize != 0 {
		return nil, errAESFileFormat
	}

	encKey, macKey := deriveAESFileKeys(key)
	mac := hmac.New(sha256.New, macKey[:])
	mac.Write(encrypted[:bodyEnd])
	if !hmac.Equal(encrypted[bodyEnd:], mac.Sum(nil)) {
		return nil, errAESFileAuthentication
	}

	prepared := prepareAES128(encKey)
	ciphertext := encrypted[aesFileHeaderSize:bodyEnd]
	plaintext := make([]byte, len(ciphertext))
	previous := encrypted[len(aesFileMagic):aesFileHeaderSize]
	for offset := 0; offset < len(ciphertext); offset += aesFileBlockSize {
		block := prepared.decrypt([aesFileBlockSize]byte(ciphertext[offset : offset+aesFileBlockSize]))
		for i := range block {
			plaintext[offset+i] = block[i] ^ previous[i]
		}
		previous = ciphertext[offset : offset+aesFileBlockSize]
	}

	padding := int(plaintext[len(plaintext)-1])
	valid := subtle.ConstantTimeLessOrEq(1, padding) & subtle.ConstantTimeLessOrEq(padding, aesFileBlockSize)
	for i := 1; i <= aesFileBlockSize; i++ {
		inPadding := subtle.ConstantTimeLessOrEq(i, padding)
		equal := subtle.ConstantTimeByteEq(plaintext[len(plaintext)-i], byte(padding))
		valid &= (1 - inPadding) | equal
	}
	if valid != 1 {
		return nil, errAESFilePadding
	}
	return plaintext[:len(plaintext)-padding], nil
}

func deriveAESFileKeys(key [32]byte) (encKey [16]byte, macKey [32]byte) {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(aesFileEncLabel))
	copy(encKey[:], mac.Sum(nil))
	mac.Reset()
	mac.Write([]byte(aesFileMACLabel))
	copy(macKey[:], mac.Sum(nil))
	return encKey, macKey
}
