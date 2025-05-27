package main

import (
	"crypto/sha256"
	"fmt"
)

func hmacSHA256(key, message []byte) []byte {
	blockSize := 64 // SHA-256 block size, the input data that it processes 

	// 1. Key normalization
	if len(key) > blockSize {
		// hash the key with sha-256
		hashSum := sha256.Sum256(key)
		// reinitialize the key to the hash sum
		key = hashSum[:]	
	}
	if len(key) < blockSize {
		// make padding with type byte and the value is blocksize - length of key
		padding := make([]byte, blockSize-len(key))
		key = append(key, padding...)
	}
	
	// 2. Create inner and outer padding
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}

	// 3. compute outer and inner hash
	// 3.1. compute inner
	inner := sha256.New()
	inner.Write(ipad)
	inner.Write(message)
	innerHash := inner.Sum(nil)

	// 3.2. compute outer
	outer := sha256.New()
	outer.Write(opad)
	outer.Write(innerHash)
	hmacResult := outer.Sum(nil)

	return hmacResult
}

func main() {
	key := []byte("supersecretkey")
	message := []byte("attackatdawn")

	mac := hmacSHA256(key, message)
	fmt.Printf("HMAC SHA256: %x\n", mac)
}
