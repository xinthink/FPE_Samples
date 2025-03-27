# Format-Preserving Encryption (FPE) Algorithms Sample

This repository contains sample implementations of Format-Preserving Encryption (FPE) algorithms in both Java and JavaScript. It demonstrates the usage of FF1 and FF3-1 ciphers, which are NIST-approved encryption methods that preserve the format of the input data.

## Overview

Format-Preserving Encryption (FPE) is a cryptographic method that encrypts data while maintaining its original format. For example, if you encrypt a credit card number, the result will still be a valid-looking credit card number. This makes FPE particularly useful for:

- Credit card number encryption
- Social security number encryption
- Custom format data encryption
- Legacy system integration where data format must be preserved

## Project Structure

```
├── FPE-Java/       # Java implementation using Bouncy Castle
└── FPE-JS/         # JavaScript implementation using ff3 library
```

## Java Implementation

### Prerequisites

- Java 8 or higher
- Maven

### Setup

1. Navigate to the Java project directory:
   ```bash
   cd FPE-Java
   ```

2. Build the project using Maven:
   ```bash
   mvn clean install
   ```

### Usage Examples

#### FF1 Cipher

```java
// Initialize FF1 cipher with custom alphabet
String alphabet = "!@#$ABCD";
FF1Cipher cipher = new FF1Cipher(alphabet);

// Encrypt and decrypt
String plainText = "AB@CD#BADC";
String cipherText = cipher.encrypt(plainText);
String decryptedText = cipher.decrypt(cipherText);

// Using numeric alphabet
cipher = new FF1Cipher(FF3Cipher.DIGITS);
plainText = "34692827";
cipherText = cipher.encrypt(plainText);
decryptedText = cipher.decrypt(cipherText);
```

#### FF3-1 Cipher

```java
// Initialize FF3-1 cipher with custom alphabet
String alphabet = FF3Cipher.DIGITS + FF3Cipher.ASCII_LOWERCASE;
FF3Cipher cipher = new FF3Cipher(alphabet);

// Encrypt and decrypt
String plainText = "123abc456def";
String cipherText = cipher.encrypt(plainText);
String decryptedText = cipher.decrypt(cipherText);
```

## JavaScript Implementation

### Prerequisites

- Node.js 12 or higher
- npm

### Setup

1. Navigate to the JavaScript project directory:
   ```bash
   cd FPE-JS
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

### Usage Examples

```javascript
const FF3Cipher = require('./index.js');

// Initialize cipher with key and tweak
const key = 'EF4359D8D580AA4F7F036D6F04FC6A94';
const tweak = '2024';
const cipher = new FF3Cipher(key, tweak);

// Encrypt and decrypt
const plaintext = '123456789';
const ciphertext = cipher.encrypt(plaintext);
const decrypted = cipher.decrypt(ciphertext);
```

## Security Considerations

- Use strong, randomly generated keys
- Keep tweak values unique for each encryption operation
- Follow NIST recommendations for minimum and maximum input lengths
- Ensure your alphabet size meets the minimum requirements for the chosen algorithm

## References

- [NIST Special Publication 800-38G](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
- [Bouncy Castle Crypto Package](https://www.bouncycastle.org/)
- [FF3 JavaScript Implementation](https://github.com/mysto/node-fpe)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
