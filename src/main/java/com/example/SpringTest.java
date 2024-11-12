package com.example;

import org.springframework.security.rsa.crypto.*;

import static org.junit.Assert.*;

public class SpringTest {

    private static final String TEST_DATA = "test data";
    private static final byte[] TEST_DATA_BYTES = TEST_DATA.getBytes();

    protected static void testAllSpringRSA() throws Exception {
        testSecretEncryptor();
    }

    private static void testSecretEncryptor() throws Exception {
        RsaSecretEncryptor secretEncryptor = new RsaSecretEncryptor(RsaAlgorithm.OAEP, "beefea");
        assertEquals(TEST_DATA, secretEncryptor.decrypt(secretEncryptor.encrypt(TEST_DATA)));
    }
}
