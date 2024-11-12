package com.example;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import static org.junit.Assert.*;

/*
Excluded Algorithms (not supported in standard JCA):
ElGamal
ECGOST
DSTU
ECNR
ECMQV
EC-Brainpool
SM2
*/

public class JcaTest {

    // Message to be encrypt/signed
    private static final String TEST_DATA = "test data";
    private static final byte[] TEST_DATA_BYTES = TEST_DATA.getBytes();

    protected static void testAllJCA() throws Exception {
        testRSAEncryptionDecryption();
        testRSASignatureVerification();
        testDSASignatureVerification();
        testECDSASignatureVerification();
        testDiffieHellmanKeyExchange();
        testECDHKeyExchange();
    }

    private static void testRSAEncryptionDecryption() throws Exception {
        // Test different key sizes
        testRSAWithKeySize(2048);
        testRSAWithKeySize(3072);
        testRSAWithKeySize(4096);
    }

    private static void testRSAWithKeySize(int keySize) throws Exception {
        // Generate KeyPair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Encrypt
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal(TEST_DATA_BYTES);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);

        assertEquals(TEST_DATA, new String(decrypted));
    }

    private static void testRSASignatureVerification() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Test different signature algorithms
        testSignature("SHA1withRSA", keyPair);
        testSignature("SHA256withRSA", keyPair);
        testSignature("SHA384withRSA", keyPair);
        testSignature("SHA512withRSA", keyPair);
    }

    // DSA Tests
    private static void testDSASignatureVerification() throws Exception {
        // Test different key sizes
        testDSAWithKeySize(1024);
        testDSAWithKeySize(2048);
        testDSAWithKeySize(3072);
    }

    private static void testDSAWithKeySize(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(keySize);
        KeyPair keyPair = keyGen.generateKeyPair();

        Signature signature = Signature.getInstance("SHA256withDSA");

        // Sign
        signature.initSign(keyPair.getPrivate());
        signature.update(TEST_DATA_BYTES);
        byte[] signatureBytes = signature.sign();

        // Verify
        signature.initVerify(keyPair.getPublic());
        signature.update(TEST_DATA_BYTES);
        assertTrue(signature.verify(signatureBytes));
    }

    // ECDSA Tests
    private static void testECDSASignatureVerification() throws Exception {
        // Test different curves
        testECDSAWithCurve("secp256r1");
        testECDSAWithCurve("secp384r1");
        testECDSAWithCurve("secp521r1");
    }

    private static void testECDSAWithCurve(String curveName) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();

        Signature signature = Signature.getInstance("SHA256withECDSA");

        // Sign
        signature.initSign(keyPair.getPrivate());
        signature.update(TEST_DATA_BYTES);
        byte[] signatureBytes = signature.sign();

        // Verify
        signature.initVerify(keyPair.getPublic());
        signature.update(TEST_DATA_BYTES);
        assertTrue(signature.verify(signatureBytes));
    }

    // Diffie-Hellman Tests
    private static void testDiffieHellmanKeyExchange() throws Exception {
        // Initialize DH parameters
        KeyPairGenerator aliceKpg = KeyPairGenerator.getInstance("DH");
        aliceKpg.initialize(2048);
        KeyPair aliceKp = aliceKpg.generateKeyPair();

        // Get DH params from Alice's public key
        DHParameterSpec dhParamSpec = ((DHPublicKey)aliceKp.getPublic()).getParams();

        // Initialize Bob's key pair generator
        KeyPairGenerator bobKpg = KeyPairGenerator.getInstance("DH");
        bobKpg.initialize(dhParamSpec);
        KeyPair bobKp = bobKpg.generateKeyPair();

        // Create shared secrets
        KeyAgreement aliceKa = KeyAgreement.getInstance("DH");
        aliceKa.init(aliceKp.getPrivate());
        aliceKa.doPhase(bobKp.getPublic(), true);
        byte[] aliceSharedSecret = aliceKa.generateSecret();

        KeyAgreement bobKa = KeyAgreement.getInstance("DH");
        bobKa.init(bobKp.getPrivate());
        bobKa.doPhase(aliceKp.getPublic(), true);
        byte[] bobSharedSecret = bobKa.generateSecret();

        assertArrayEquals(aliceSharedSecret, bobSharedSecret);
    }

    // ECDH Tests
    private static void testECDHKeyExchange() throws Exception {
        // Initialize EC parameters
        KeyPairGenerator aliceKpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        aliceKpg.initialize(ecSpec);
        KeyPair aliceKp = aliceKpg.generateKeyPair();

        // Initialize Bob's key pair generator
        KeyPairGenerator bobKpg = KeyPairGenerator.getInstance("EC");
        bobKpg.initialize(ecSpec);
        KeyPair bobKp = bobKpg.generateKeyPair();

        // Create shared secrets
        KeyAgreement aliceKa = KeyAgreement.getInstance("ECDH");
        aliceKa.init(aliceKp.getPrivate());
        aliceKa.doPhase(bobKp.getPublic(), true);
        byte[] aliceSharedSecret = aliceKa.generateSecret();

        KeyAgreement bobKa = KeyAgreement.getInstance("ECDH");
        bobKa.init(bobKp.getPrivate());
        bobKa.doPhase(aliceKp.getPublic(), true);
        byte[] bobSharedSecret = bobKa.generateSecret();

        assertArrayEquals(aliceSharedSecret, bobSharedSecret);
    }

    // Helper method for signature testing
    private static void testSignature(String algorithm, KeyPair keyPair) throws Exception {
        Signature signature = Signature.getInstance(algorithm);

        // Sign
        signature.initSign(keyPair.getPrivate());
        signature.update(TEST_DATA_BYTES);
        byte[] signatureBytes = signature.sign();

        // Verify
        signature.initVerify(keyPair.getPublic());
        signature.update(TEST_DATA_BYTES);
        assertTrue(signature.verify(signatureBytes));
    }

}
