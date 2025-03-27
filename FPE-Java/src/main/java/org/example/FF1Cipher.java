package org.example;

import com.privacylogistics.FF3Cipher;
import org.bouncycastle.crypto.AlphabetMapper;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.fpe.FPEEngine;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.BasicAlphabetMapper;
import org.bouncycastle.util.encoders.Hex;

import java.security.GeneralSecurityException;

import static com.privacylogistics.FF3Cipher.DOMAIN_MIN;

public class FF1Cipher {
    private static final String KEY = "2B7E151628AED2A6ABF7158809CF4F3C";
    private static final String TWEAK = "2024";

    private final FPEEngine engine;
    private final FPEParameters fpeParameters;
    private final AlphabetMapper alphabetMapper;
    private final CipherSettings settings;

    public FF1Cipher(String alphabet) {
        this.alphabetMapper = new BasicAlphabetMapper(alphabet);
        this.fpeParameters = new FPEParameters(
                new KeyParameter(Hex.decode(KEY)),
                alphabetMapper.getRadix(),
                Hex.decode(TWEAK)
        );
        this.engine = new FPEFF1Engine(AESEngine.newInstance());

        // Based on the code, I need to solve the equation `Math.pow(radix, 2) >= 1000000` to find the minimum radix value when var2 is fixed at 2.
        //
        //Let's solve for radix:
        //- Math.pow(radix, 2) ≥ 1000000
        //- radix² ≥ 1000000
        //- radix ≥ √1000000
        //- radix ≥ 1000
        //
        //So for var2 (the exponent) to be 2, the radix (var1) must be at least 1000.
        //
        //In the context of the code, this means the alphabet length would need to be at least 1000 characters for the minimum length requirement to be just 2 characters.
        int radix = fpeParameters.getRadix();
        int minLen = (int) Math.ceil(Math.log(DOMAIN_MIN) / Math.log(radix));
        int maxLen = Integer.MAX_VALUE; // (int) (2.0 * Math.floor(Math.log(Math.pow(2.0, 96.0)) / Math.log(radix)));
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

    static void testFF1Cipher() throws GeneralSecurityException {
        System.out.println("\n------ Bouncy Castle FF1 Cipher Tests ------");

        String alphabet;
        FF1Cipher cipher;
        String plainText;
        String cipherText;
        String decryptedText;

        alphabet = "!@#$ABCD";
        cipher = new FF1Cipher(alphabet);
        System.out.println("\nFF1Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);

        plainText = "AB@CD#BADC";
        cipherText = cipher.encrypt(plainText);
        decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " -> " + cipherText + " -> " + decryptedText);

        alphabet = FF3Cipher.DIGITS;
        cipher = new FF1Cipher(alphabet);
        System.out.println("\nFF1Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);

        plainText = "34692827";
        cipherText = cipher.encrypt(plainText);
        decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " -> " + cipherText + " -> " + decryptedText);

        alphabet = FF3Cipher.DIGITS + FF3Cipher.ASCII_LOWERCASE + FF3Cipher.ASCII_UPPERCASE + "-_/~!@#$%^&*(){}[]";
        cipher = new FF1Cipher(alphabet);
        System.out.println("\nFF1Cipher: alphabet=\"" + alphabet + "\", " + cipher.settings);

        plainText = "A3/9231]2cd*E129A39231]2cd}E129A39231]2cd*E129A39231]2cd}E129A39231]2cd*E129A39231]2cd}E129A39231]2cd*E129A39231]2cd}E129";
        cipherText = cipher.encrypt(plainText);
        decryptedText = cipher.decrypt(cipherText);
        System.out.println(plainText + " (len=" + plainText.length() + ") -> " + cipherText + " -> " + decryptedText);

        System.out.println("\n------ END ------\n");
    }
}
