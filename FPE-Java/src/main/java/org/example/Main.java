package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Main {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        try {
            // Mysto implementation
            MystoFF3Cipher.testMystoCipher();

            // Bouncy Castle FF1
            FF1Cipher.testFF1Cipher();

            // Bouncy Castle FF3-1
            FF3Cipher.testFF3Cipher();
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }
}
