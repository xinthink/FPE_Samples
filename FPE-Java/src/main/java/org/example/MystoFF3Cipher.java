package org.example;

import com.privacylogistics.FF3Cipher;

import java.security.GeneralSecurityException;

import static com.privacylogistics.FF3Cipher.DOMAIN_MIN;

public class MystoFF3Cipher {
    private static final String KEY = "2DE79D232DF5585D68CE47882AE256D6";
    private static final String TWEAK = "CBD09280979564";

    private final FF3Cipher cipher;
    private final CipherSettings settings;

    public MystoFF3Cipher(String alphabet) {
        this.cipher = new FF3Cipher(KEY, TWEAK, alphabet);
        int radix = alphabet.length();
        int minLen = (int) Math.ceil(Math.log(DOMAIN_MIN) / Math.log(radix));
        int maxLen = (int) (2.0 * Math.floor(Math.log(Math.pow(2.0, 96.0)) / Math.log(radix)));
        this.settings = new CipherSettings(alphabet.length(), minLen, maxLen);
    }

    public CipherSettings getSettings() {
        return settings;
    }

    public String encrypt(String plaintext) throws GeneralSecurityException {
        return cipher.encrypt(plaintext);
    }

    public String decrypt(String ciphertext) throws GeneralSecurityException {
        return cipher.decrypt(ciphertext);
    }

    static void testMystoCipher() throws GeneralSecurityException {
        System.out.println("\n------ Mysto FF3 Cipher Tests ------");

        String alphabet = "ABCD";
        MystoFF3Cipher cipher = new MystoFF3Cipher(alphabet);
        System.out.println("\nMystoFF3Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);

        String plainText = "A392312e3f";
        String cipherText = cipher.encrypt(plainText);
        String decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " -> " + cipherText + " -> " + decryptedText);

        alphabet = FF3Cipher.DIGITS;
        cipher = new MystoFF3Cipher(alphabet);
        System.out.println("\nMystoFF3Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);

        plainText = "39A2312";
        cipherText = cipher.encrypt(plainText);
        decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " -> " + cipherText + " -> " + decryptedText);

        alphabet = FF3Cipher.DIGITS + FF3Cipher.ASCII_LOWERCASE + FF3Cipher.ASCII_UPPERCASE;
        cipher = new MystoFF3Cipher(alphabet);
        System.out.println("\nMystoFF3Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);

        plainText = "A392312cdE129A39231cdE9A392cdE19";
        cipherText = cipher.encrypt(plainText);
        decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " -> " + cipherText + " -> " + decryptedText);

        System.out.println("\n------ END ------\n");
    }
}
