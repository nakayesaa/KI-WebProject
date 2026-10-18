package utils

import "os"

type State [4][4]byte
var AESKEY := os.Getenv("AES_KEY")
func BytesToState(input [16]byte) State {
	var state State
	for i := range 16 {
		row := i % 4
		col := i / 4

		state[row][col] = input[i]
	}

	return state
}

func GFMul(a, b byte) byte {
	var result byte

	for i := range 8 {
		if b&1 != 0 {
			result ^= a
		}

		highbit := a & 0x80

		a <<= 1

		if highbit != 0 {
			a ^= 0x1B
		}

		b >>= 1
	}

	return result
}

func GfInverse(a byte) byte {
	if a == 0 {
		return 0
	}

	for i := 1; i < 256; i++ {
		if GFMul(a, byte(i)) == 1 {
			return byte(i)
		}
	}

	panic("multiplicative inverse not found")
}

// Cyclic Rotate Left
func RotateLeft(b byte, n uint) byte {
	return (b << n) | (b >> (8 - n))
}

func AffineTransform(b byte) byte {
	return b ^
		RotateLeft(b, 1) ^
		RotateLeft(b, 2) ^
		RotateLeft(b, 3) ^
		RotateLeft(b, 4) ^
		0x63
}

func GenerateSBox() [256]byte {
	var sbox [256]byte

	for i := 0; i < 256; i++ {
		sbox[i] = AffineTransform(GfInverse(byte(i)))
	}

	return sbox
}

// generate RoundKey
func KeyExpansion(key [16]byte) [11]State {
	var words [44][4]byte
	sbox := GenerateSBox()

	for i := range 4 {
		copy(words[i][:], key[i*4:(i+1)*4])
	}

	//rcon for other word
	rcon := [10]byte{
		0x01, 0x02, 0x04, 0x08, 0x10,
		0x20, 0x40, 0x80, 0x1B, 0x36,
	}

	for i := 4; i < 44; i++ {
		temp := words[i-1]

		// generate template for new roundKey
		if i%4 == 0 {
			//RotWord
			temp = [4]byte{
				temp[1], temp[2], temp[3], temp[0],
			}

			//subword
			for j := range 4 {
				temp[j] = sbox[temp[j]]
			}

			// rcon
			temp[0] ^= rcon[i/4-1]
		}

		// generate new word
		for j := range 4 {
			words[i][j] = words[i-4][j] ^ temp[j]
		}
	}

	var roundKeys [11]State

	for round := range 11 {
		for col := range 4 {
			for row := range 4 {
				roundKeys[round][row][col] = words[round*4+col][row]
			}
		}
	}

	return roundKeys
}

func AesEncrypt(plainText [16]byte) [16]byte {
	state := BytesToState(plainText)
	KeyString := os.Getenv("AES_KEY")

	if len(KeyString) > 16 {
		panic("AES_KEY must be exactly 16 bytes")
	}
	var key [16]byte
	copy(key[:], []byte(keyString))

	roundKey := KeyExpansion(key)



}
