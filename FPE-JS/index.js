const FF3Cipher = require('ff3/lib/FF3Cipher');

const key = "EF4359D8D580AA4F7F036D6F04FC6A94"
const tweak = "D8E7920AFA330A"
const c = new FF3Cipher(key, tweak, 36)

let plaintext = "4000001234567899"
let ciphertext = c.encrypt(plaintext)
let decrypted = c.decrypt(ciphertext)

console.log("%s -> %s -> %s", plaintext, ciphertext, decrypted)

plaintext = "Hello12.3helLo"
ciphertext = c.encrypt(plaintext)
decrypted = c.decrypt(ciphertext)

console.log("%s -> %s -> %s", plaintext, ciphertext, decrypted)

// plaintext = "1"
// ciphertext = c.encrypt(plaintext)
// decrypted = c.decrypt(ciphertext)

console.log("%s -> %s -> %s", plaintext, ciphertext, decrypted)
