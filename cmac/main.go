
package main

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
)

// xorBlocks returns a ⊕ b
func xorBlocks(a, b []byte) []byte {
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res
}

// leftShiftOneBit shifts a 16-byte block left by 1 bit
func leftShiftOneBit(input []byte) []byte {
	output := make([]byte, len(input))
	overflow := byte(0)
	for i := len(input) - 1; i >= 0; i-- {
		output[i] = (input[i] << 1) | overflow
		overflow = (input[i] & 0x80) >> 7
	}
	return output
}

// generateSubkeys derives K1 and K2 from AES(key, 0^128)
func generateSubkeys(key []byte) (k1, k2 []byte) {
	const blockSize = 16
	Rb := []byte{0x87}

	cipher, _ := aes.NewCipher(key)
	zeroBlock := make([]byte, blockSize)
	L := make([]byte, blockSize)
	cipher.Encrypt(L, zeroBlock)

	k1 = leftShiftOneBit(L)
	if (L[0] & 0x80) != 0 {
		k1[len(k1)-1] ^= Rb[0]
	}

	k2 = leftShiftOneBit(k1)
	if (k1[0] & 0x80) != 0 {
		k2[len(k2)-1] ^= Rb[0]
	}

	return
}

// padBlock appends 0x80 followed by 0x00 padding to fill 16 bytes
func padBlock(block []byte) []byte {
	padding := make([]byte, 16-len(block))
	padding[0] = 0x80
	return append(block, padding...)
}

func cmacAES128(key, msg []byte) []byte {
	const blockSize = 16

	k1, k2 := generateSubkeys(key)

	n := (len(msg) + blockSize - 1) / blockSize
	lastBlockComplete := len(msg)%blockSize == 0 && len(msg) != 0

	// Prepare blocks
	var lastBlock []byte
	if lastBlockComplete {
		lastBlock = xorBlocks(msg[(n-1)*blockSize:], k1)
	} else {
		last := padBlock(msg[(n-1)*blockSize:])
		lastBlock = xorBlocks(last, k2)
	}

	// CBC-MAC
	cipher, _ := aes.NewCipher(key)
	X := make([]byte, blockSize)
	Y := make([]byte, blockSize)

	for i := 0; i < n-1; i++ {
		block := msg[i*blockSize : (i+1)*blockSize]
		Y = xorBlocks(X, block)
		cipher.Encrypt(X, Y)
	}

	Y = xorBlocks(X, lastBlock)
	cipher.Encrypt(X, Y)

	return X
}

func main() {
	key := []byte("thisis16bytekey!")
	message := []byte("message to cmac")

	mac := cmacAES128(key, message)
	fmt.Printf("CMAC-AES128: %s\n", hex.EncodeToString(mac))
}
