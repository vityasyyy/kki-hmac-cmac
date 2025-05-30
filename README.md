# KKI KOM A 

Kelompok 4:
```bash
    1. Andreandhiki Riyanta Putra (23/517511/PA/22191)
    2. Andrian Danar Perdana (23/513040/PA/21917)
    3. Daffa Indra Wibowo (23/518514/PA/22253)
    4. Muhammad Argya Vityasy(23/522547/PA/22475)
```
Course: Kriptografi dan Keamanan Informasi KOM A

Lecturer: Drs. Edi Winarko, M.Sc.,Ph.D.

# Cryptographic Message Authentication Codes (MAC) Implementation

A comprehensive implementation of two popular Message Authentication Code (MAC) algorithms in Go: HMAC-SHA256 and CMAC-AES128. This project demonstrates how these cryptographic primitives work to ensure message integrity and authenticity.

## 🔐 Overview

Message Authentication Codes (MACs) are cryptographic algorithms that provide both data integrity and authenticity assurance. This repository contains from-scratch implementations of:

- **HMAC-SHA256**: Hash-based Message Authentication Code using SHA-256
- **CMAC-AES128**: Cipher-based Message Authentication Code using AES-128

Both implementations include complete examples demonstrating:
- ✅ Legitimate message authentication
- 🚨 Man-in-the-Middle (MITM) attack detection
- 🔍 Integrity verification processes

## 📁 Project Structure

```
├── LICENSE
├── README.md
├── cmac/
│   ├── go.mod
│   ├── main.go
│   └── cmac (executable)
└── hmac/
    ├── go.mod
    ├── main.go
    └── hmac (executable)
```

## 🚀 Quick Start

### Prerequisites

- Go 1.23.1 or later
- Basic understanding of cryptographic concepts

### Running the Examples

#### HMAC-SHA256 Example
```bash
cd hmac
go run main.go
```

#### CMAC-AES128 Example
```bash
cd cmac
go run main.go
```

## 📚 Algorithm Details

### HMAC-SHA256

HMAC (Hash-based Message Authentication Code) combines a cryptographic hash function with a secret key. Our implementation follows RFC 2104:

**Key Features:**
- Uses SHA-256 as the underlying hash function
- 64-byte block size processing
- Automatic key normalization (padding/hashing)
- Inner and outer hash computation with different padding constants

**Security Properties:**
- Provides both integrity and authenticity
- Resistant to length extension attacks
- Computationally infeasible to forge without the secret key

### CMAC-AES128

CMAC (Cipher-based Message Authentication Code) is based on block ciphers and follows NIST SP 800-38B:

**Key Features:**
- Uses AES-128 as the underlying block cipher
- 16-byte block processing
- Subkey generation (K1, K2) for different message lengths
- Proper padding for incomplete blocks

**Security Properties:**
- Provably secure under standard cryptographic assumptions
- No length extension vulnerabilities
- Efficient for hardware implementations

## 🛡️ Security Demonstration

Both implementations include MITM attack simulations that demonstrate:

1. **Legitimate Flow**: Sender → Receiver with valid MAC
2. **Attack Scenario**: MITM modifies message but cannot forge valid MAC
3. **Detection**: Receiver detects tampering through MAC verification failure

### Example Output

```
Sender:
  Message: Attack at dawn
  Tag: a1b2c3d4e5f6...

MITM:
  Tampered Message: Bttack at dawn
  Tag (unchanged): a1b2c3d4e5f6...

Receiver: ❌ Integrity Check Failed (MITM detected!)
```

## 🔧 Implementation Details

### HMAC Core Functions

- `hmacSHA256(key, message)`: Main HMAC computation
- Key normalization and padding
- Inner/outer hash computation
- XOR operations with IPAD (0x36) and OPAD (0x5c)

### CMAC Core Functions

- `generateSubkeys(key)`: Derives K1 and K2 subkeys
- `leftShiftOneBit(input)`: Bit manipulation for subkey generation
- `padBlock(block)`: Applies 10* padding for incomplete blocks
- `xorBlocks(a, b)`: XOR operation for block processing

## 📖 Educational Value

This project is designed for:

- **Cryptography Students**: Understanding MAC algorithm internals
- **Security Engineers**: Reference implementation for security analysis
- **Go Developers**: Learning cryptographic programming patterns
- **Researchers**: Baseline for performance comparisons

## ⚠️ Important Notes

- **Educational Purpose**: These implementations are for learning and demonstration
- **Production Use**: Use standard library implementations (`crypto/hmac`, `crypto/cipher`) for production
- **Security Audit**: Custom cryptographic implementations should undergo professional security review

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📚 References

- [RFC 2104: HMAC: Keyed-Hashing for Message Authentication](https://tools.ietf.org/html/rfc2104)
- [NIST SP 800-38B: The CMAC Mode for Authentication](https://csrc.nist.gov/publications/detail/sp/800-38b/final)
- [FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)](https://csrc.nist.gov/publications/detail/fips/198/1/final)

---
