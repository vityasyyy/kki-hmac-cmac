package main

import (
	"crypto/sha256"
	"fmt"
	"encoding/hex"
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

// Simulate a trusted sender
func sender(key, message []byte) (msg, tag []byte) {
	tag = hmacSHA256(key, message)
	return message, tag
}

// Simulate MITM trying to tamper the message
func mitmTamper(originalMsg, originalTag []byte) (msg, tag []byte) {
	// Tamper with the message
	tamperedMsg := make([]byte, len(originalMsg))
	copy(tamperedMsg, originalMsg)
	tamperedMsg[0] ^= 0x01 // change one byte

	// MITM doesn't know the key, so they cannot forge a valid tag
	return tamperedMsg, originalTag
}

// Simulate the receiver
func receiver(key, receivedMsg, receivedTag []byte) bool {
	expectedTag := hmacSHA256(key, receivedMsg)
	return hex.EncodeToString(expectedTag) == hex.EncodeToString(receivedTag)
}

func main() {
	key := []byte("supersecretkey")
	message := []byte("Attack at dawn")

	// Sender sends message + tag
	msg, tag := sender(key, message)
	fmt.Printf("Sender:\n  Message: %s\n  Tag: %x\n\n", msg, tag)

	// MITM modifies message but reuses tag
	tamperedMsg, tamperedTag := mitmTamper(msg, tag)
	fmt.Printf("MITM:\n  Tampered Message: %s\n  Tag (unchanged): %x\n\n", tamperedMsg, tamperedTag)

	// Receiver verifies integrity
	if receiver(key, tamperedMsg, tamperedTag) {
		fmt.Println("Receiver: ✅ Integrity Verified (SHOULD NOT HAPPEN!)")
	} else {
		fmt.Println("Receiver: ❌ Integrity Check Failed (MITM detected!)")
	}
}
