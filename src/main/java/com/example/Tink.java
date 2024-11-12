package com.example;

import com.google.crypto.tink.*;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.hybrid.HybridDecryptFactory;
import com.google.crypto.tink.hybrid.HybridEncryptFactory;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import com.google.crypto.tink.signature.PublicKeySignFactory;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.crypto.tink.signature.SignatureKeyTemplates;

import static org.junit.Assert.assertEquals;

public class Tink {

    // Message to be encrypt/signed
    private static final String TEST_DATA = "test data";
    private static final byte[] TEST_DATA_BYTES = TEST_DATA.getBytes();

    protected static void testAllTink() throws Exception {
        TinkConfig.register();
        testHybrid();
        testDigitalSignature();
    }

    private static void testHybrid() throws Exception {
        // symmetric key to encrypt the plaintext and a public key to encrypt the symmetric key only

        KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(
                HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256);
        KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();

        String contextInfo = "Tink";

        HybridEncrypt hybridEncrypt = HybridEncryptFactory.getPrimitive(publicKeysetHandle);
        HybridDecrypt hybridDecrypt = HybridDecryptFactory.getPrimitive(privateKeysetHandle);

        byte[] ciphertext = hybridEncrypt.encrypt(TEST_DATA_BYTES, contextInfo.getBytes());
        byte[] plaintextDecrypted = hybridDecrypt.decrypt(ciphertext, contextInfo.getBytes());

        assertEquals(TEST_DATA, new String(plaintextDecrypted));
    }

    private static void testDigitalSignature() throws Exception {
        KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
        KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();

        PublicKeySign signer = PublicKeySignFactory.getPrimitive(privateKeysetHandle);
        PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(publicKeysetHandle);

        byte[] signature = signer.sign(TEST_DATA_BYTES);
        verifier.verify(signature, TEST_DATA_BYTES);
    }
}
