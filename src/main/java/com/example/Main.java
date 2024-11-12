package com.example;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("\n'test data' string is used as a sample string for encryption for all tests.\n");
        // Bouncy Castle Tests
        System.out.println("\n=== Bouncy Castle Tests - START ===");
        BouncyCastleProvider bc = new BouncyCastleProvider();
        Security.addProvider(bc);
        BouncyCastleTest.testAllBouncyCastle();
        Security.removeProvider(bc.getName());
        System.out.println("\n=== Bouncy Castle Tests - COMPLETED ===");

        // Java Cryptography Architecture (JCA) Tests
        System.out.println("\n=== Java Cryptography Architecture Tests - START===");
        JcaTest.testAllJCA();
        System.out.println("\n=== Java Cryptography Architecture Tests - COMPLETED ===");

        // Tink Tests
        System.out.println("\n=== Tink Tests - START===");
        Tink.testAllTink();
        System.out.println("\n=== Tink Tests - COMPLETED ===");

        // Nimbus Jose Tests
        System.out.println("\n=== Nimbus Jose Tests - START===");
        NimbusJoseTest.testAllNimbusJose();
        System.out.println("\n=== Nimbus Jose Tests - COMPLETED ===");

        // Spring RSA Tests
        System.out.println("\n=== Spring RSA Tests - START===");
        SpringTest.testAllSpringRSA();
        System.out.println("\n=== Spring RSA Tests - COMPLETED ===");
    }
}

