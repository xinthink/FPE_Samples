package org.example;

import org.bouncycastle.crypto.AlphabetMapper;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.fpe.FPEEngine;
import org.bouncycastle.crypto.fpe.FPEFF3_1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.BasicAlphabetMapper;
import org.bouncycastle.util.encoders.Hex;

import java.security.GeneralSecurityException;

import static com.privacylogistics.FF3Cipher.DOMAIN_MIN;

class FF3Cipher {
    private static final String KEY = "2B7E151628AED2A6ABF7158809CF4F3C";
    private static final String TWEAK = "CBD09280979564";

    private final FPEEngine engine;
    private final FPEParameters fpeParameters;
    private final AlphabetMapper alphabetMapper;
    private final CipherSettings settings;

    public FF3Cipher(String alphabet) {
        this.alphabetMapper = new BasicAlphabetMapper(alphabet);
        this.fpeParameters = new FPEParameters(
                new KeyParameter(Hex.decode(KEY)),
                alphabetMapper.getRadix(),
                Hex.decode(TWEAK)
        );
        this.engine = new FPEFF3_1Engine(AESEngine.newInstance());

        int radix = fpeParameters.getRadix();
        int minLen = (int) Math.ceil(Math.log(DOMAIN_MIN) / Math.log(radix));
        int maxLen = (int) (2.0 * Math.floor(Math.log(Math.pow(2.0, 96.0)) / Math.log(radix)));
        this.settings = new CipherSettings(alphabet.length(), minLen, maxLen);
    }

    public CipherSettings getSettings() {
        return settings;
    }

    public String encrypt(String plaintext) {
        engine.init(true, fpeParameters);
        byte[] input = alphabetMapper.convertToIndexes(plaintext.toCharArray());
        byte[] result = new byte[input.length];
        engine.processBlock(input, 0, input.length, result, 0);
        return new String(alphabetMapper.convertToChars(result));
    }

    public String decrypt(String ciphertext) {
        engine.init(false, fpeParameters);
        byte[] input = alphabetMapper.convertToIndexes(ciphertext.toCharArray());
        byte[] result = new byte[input.length];
        engine.processBlock(input, 0, input.length, result, 0);
        return new String(alphabetMapper.convertToChars(result));
    }

    static void testFF3Cipher() throws GeneralSecurityException {
        System.out.println("\n------ Bouncy Castle FF3-1 Cipher Tests ------");

        String alphabet;
        FF3Cipher cipher;
        String plainText;
        String cipherText;
        String decryptedText;

        alphabet = "!@#$ABCD";
        cipher = new FF3Cipher(alphabet);
        System.out.println("\nFF3Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);

        plainText = "AB@CD#BADC";
        cipherText = cipher.encrypt(plainText);
        decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " -> " + cipherText + " -> " + decryptedText);

        alphabet = com.privacylogistics.FF3Cipher.DIGITS;
        cipher = new FF3Cipher(alphabet);
        System.out.println("\nFF3Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);


        plainText = "34692827";
        cipherText = cipher.encrypt(plainText);
        decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " -> " + cipherText + " -> " + decryptedText);

        alphabet = com.privacylogistics.FF3Cipher.DIGITS + com.privacylogistics.FF3Cipher.ASCII_LOWERCASE + com.privacylogistics.FF3Cipher.ASCII_UPPERCASE + "-_/~!@#$%^&*(){}[]";
        cipher = new FF3Cipher(alphabet);
        System.out.println("\nFF3Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);

        plainText = "A3/9231]2cd*E129A39-231_Eae6^$";
        cipherText = cipher.encrypt(plainText);
        decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " (len=" + plainText.length() + ") -> " + cipherText + " -> " + decryptedText);

        plainText = "34692827";
        cipherText = cipher.encrypt(plainText);
        decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " -> " + cipherText + " -> " + decryptedText);

        alphabet = com.privacylogistics.FF3Cipher.DIGITS + com.privacylogistics.FF3Cipher.ASCII_LOWERCASE + com.privacylogistics.FF3Cipher.ASCII_UPPERCASE + "-_/~!@#$%^&*(){}[]";
        cipher = new FF3Cipher(alphabet);
        System.out.println("\nFF3Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);

        try {
            plainText =
                    "A3/9231]2cd*E129A39231]2cd}E129A39231]2cd*E129A39231]2cd}E129A39231]2cd*E129A39231]2cd}E129A39231]2cd*E129A39231]2cd}E129";
            cipherText = cipher.encrypt(plainText);
            decryptedText = cipher.decrypt(cipherText);
            System.out.println(plainText + " (len=" + plainText.length() + ") -> " + cipherText + " -> " + decryptedText);
        } catch (Exception e) {
            System.out.println(plainText + " the input length " + plainText.length() + " exceeds upper limit: " + e.getMessage());
        }

        System.out.println("\n------ END ------\n");
    }
}
