package utils

type State [4][4]byte

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

	for range 8 {
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
func KeyExpansion(key [16]byte) ([11]State, [256]byte) {
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

	return roundKeys, sbox
}

func SubBytes(state *State, sbox *[256]byte) {
	for row := range 4 {
		for col := range 4 {
			state[row][col] = sbox[state[row][col]]
		}
	}
}

func ShiftRow(state *State) {
	for row := 1; row < 4; row++ {
		var temp [4]byte

		for col := 0; col < 4; col++ {
			temp[col] = state[row][(col+row)%4]
		}
		state[row] = temp
	}
}

func MixColumns(state *State) {
	for col := 0; col < 4; col++ {
		a0 := state[0][col]
		a1 := state[1][col]
		a2 := state[2][col]
		a3 := state[3][col]

		b0 := GFMul(0x02, a0) ^ GFMul(0x03, a1) ^ a2 ^ a3
		b1 := a0 ^ GFMul(0x02, a1) ^ GFMul(0x03, a2) ^ a3
		b2 := a0 ^ a1 ^ GFMul(0x02, a2) ^ GFMul(0x03, a3)
		b3 := GFMul(0x03, a0) ^ a1 ^ a2 ^ GFMul(0x02, a3)

		state[0][col] = b0
		state[1][col] = b1
		state[2][col] = b2
		state[3][col] = b3
	}
}

func AddRoundKey(state *State, roundKey *State) {
	for row := range 4 {
		for col := range 4 {
			state[row][col] ^= roundKey[row][col]
		}
	}
}

func StateToBytes(state State) [16]byte {
	var result [16]byte

	for i := range 16 {
		row := i % 4
		col := i / 4

		result[i] = state[row][col]
	}

	return result
}

func AesEncrypt128(plainText [16]byte, key [16]byte) [16]byte {
	state := BytesToState(plainText)

	roundKeys, sbox := KeyExpansion(key)

	// Initial Round
	AddRoundKey(&state, &roundKeys[0])

	// Round 1–9
	for round := 1; round < 10; round++ {
		SubBytes(&state, &sbox)
		ShiftRow(&state)
		MixColumns(&state)
		AddRoundKey(&state, &roundKeys[round])
	}

	// Final Round (10)
	SubBytes(&state, &sbox)
	ShiftRow(&state)
	AddRoundKey(&state, &roundKeys[10])

	return StateToBytes(state)
}

func GenerateInverseSBox(sbox [256]byte) [256]byte {
	var inverseSBox [256]byte

	for i, value := range sbox {
		inverseSBox[value] = byte(i)
	}

	return inverseSBox
}

func InvSubBytes(state *State, inverseSBox *[256]byte) {
	for row := range 4 {
		for col := range 4 {
			state[row][col] = inverseSBox[state[row][col]]
		}
	}
}

func InvShiftRow(state *State) {
	for row := 1; row < 4; row++ {
		var temp [4]byte

		for col := range 4 {
			temp[col] = state[row][(col-row+4)%4]
		}
		state[row] = temp
	}
}

func InvMixColumns(state *State) {
	for col := range 4 {
		a0 := state[0][col]
		a1 := state[1][col]
		a2 := state[2][col]
		a3 := state[3][col]

		state[0][col] = GFMul(0x0e, a0) ^ GFMul(0x0b, a1) ^ GFMul(0x0d, a2) ^ GFMul(0x09, a3)
		state[1][col] = GFMul(0x09, a0) ^ GFMul(0x0e, a1) ^ GFMul(0x0b, a2) ^ GFMul(0x0d, a3)
		state[2][col] = GFMul(0x0d, a0) ^ GFMul(0x09, a1) ^ GFMul(0x0e, a2) ^ GFMul(0x0b, a3)
		state[3][col] = GFMul(0x0b, a0) ^ GFMul(0x0d, a1) ^ GFMul(0x09, a2) ^ GFMul(0x0e, a3)
	}
}

func AesDecrypt128(cipherText [16]byte, key [16]byte) [16]byte {
	state := BytesToState(cipherText)

	roundKeys, sbox := KeyExpansion(key)
	inverseSBox := GenerateInverseSBox(sbox)

	AddRoundKey(&state, &roundKeys[10])

	for round := 9; round > 0; round-- {
		InvShiftRow(&state)
		InvSubBytes(&state, &inverseSBox)
		AddRoundKey(&state, &roundKeys[round])
		InvMixColumns(&state)
	}

	InvShiftRow(&state)
	InvSubBytes(&state, &inverseSBox)
	AddRoundKey(&state, &roundKeys[0])

	return StateToBytes(state)
}
