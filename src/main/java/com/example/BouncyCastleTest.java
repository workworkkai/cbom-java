package com.example;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECMQVBasicAgreement;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.MQVPrivateParameters;
import org.bouncycastle.crypto.params.MQVPublicParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ECNRSigner;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;


public class BouncyCastleTest {

    // Message to be encrypt/signed
    private static final String TEST_DATA = "test data";
    private static final byte[] TEST_DATA_BYTES = TEST_DATA.getBytes();
    private static final SecureRandom random = new SecureRandom();

    protected static void testAllBouncyCastle() throws Exception {
        testRSA();
        testDSA();
        testECDSA();
        testElGamal();
        testDH();
        testECDH();
        testECGOST3410();
        testDSTU4145();
        testECNR();
        testECMQV();
        testSM2();
        testMiscECC();
    }

    private static void testRSA() throws Exception {
        System.out.println("\n=== RSA Tests ===");

        // Method 1: Using low-level BC API
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        BigInteger publicExponent = new BigInteger("10001", 16);
        RSAKeyGenerationParameters params = new RSAKeyGenerationParameters(
                publicExponent, random, 2048, 12);
        rsaGen.init(params);
        AsymmetricCipherKeyPair keyPair1 = rsaGen.generateKeyPair();
        RSAKeyParameters publicKey1 = (RSAKeyParameters) keyPair1.getPublic();

        PKCS1Encoding cipher1 = new PKCS1Encoding(new RSAEngine());
        cipher1.init(true, publicKey1);
        byte[] encrypted1 = cipher1.processBlock(TEST_DATA_BYTES, 0, TEST_DATA_BYTES.length);
        System.out.println("RSA Method 1 (Low-level): " +
                Base64.getEncoder().encodeToString(encrypted1));

        // Method 2: Using JCE API with OAEP
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGen.initialize(2048);
        KeyPair keyPair2 = keyPairGen.generateKeyPair();

        Cipher cipher2 = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipher2.init(Cipher.ENCRYPT_MODE, keyPair2.getPublic());
        byte[] encrypted2 = cipher2.doFinal(TEST_DATA_BYTES);
        System.out.println("RSA Method 2 (OAEP): " +
                Base64.getEncoder().encodeToString(encrypted2));

        // Method 3: Using JCE API with PKCS1 Padding
        Cipher cipher3 = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher3.init(Cipher.ENCRYPT_MODE, keyPair2.getPublic());
        byte[] encrypted3 = cipher3.doFinal(TEST_DATA_BYTES);
        System.out.println("RSA Method 3 (PKCS1): " +
                Base64.getEncoder().encodeToString(encrypted3));
    }

    private static void testDSA() throws Exception {
        System.out.println("\n=== DSA Tests ===");

        // Method 1: Using low-level BC API
        DSAParametersGenerator parametersGenerator = new DSAParametersGenerator();
        parametersGenerator.init(2048, 80, random);
        DSAParameters parameters = parametersGenerator.generateParameters();

        DSAKeyPairGenerator dsaGen = new DSAKeyPairGenerator();
        DSAKeyGenerationParameters params = new DSAKeyGenerationParameters(
                random, parameters);
        dsaGen.init(params);
        AsymmetricCipherKeyPair keyPair1 = dsaGen.generateKeyPair();
        System.out.println("DSA Method 1 (Low-level) - Generated KeyPair: " +
                keyPair1.getPublic().toString());

        // Method 2: Using JCE API
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA", "BC");
        keyPairGen.initialize(2048);
        KeyPair keyPair2 = keyPairGen.generateKeyPair();

        Signature signature = Signature.getInstance("DSA", "BC");
        signature.initSign(keyPair2.getPrivate());
        signature.update(TEST_DATA_BYTES);
        byte[] signed = signature.sign();
        System.out.println("DSA Method 2 (JCE) - Signature: " +
                Base64.getEncoder().encodeToString(signed));
    }

    private static void testECDSA() throws Exception {
        System.out.println("\n=== ECDSA Tests ===");

        // Method 1: Using named curves
        KeyPairGenerator keyPairGen1 = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        keyPairGen1.initialize(ecSpec, random);
        KeyPair keyPair1 = keyPairGen1.generateKeyPair();

        Signature signature1 = Signature.getInstance("SHA256withECDSA", "BC");
        signature1.initSign(keyPair1.getPrivate());
        signature1.update(TEST_DATA_BYTES);
        byte[] signed1 = signature1.sign();
        System.out.println("ECDSA Method 1 (Named Curve): " +
                Base64.getEncoder().encodeToString(signed1));

        // Method 2: Using explicit curve parameters
        KeyPairGenerator keyPairGen2 = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGen2.initialize(256);
        KeyPair keyPair2 = keyPairGen2.generateKeyPair();

        Signature signature2 = Signature.getInstance("SHA384withECDSA", "BC");
        signature2.initSign(keyPair2.getPrivate());
        signature2.update(TEST_DATA_BYTES);
        byte[] signed2 = signature2.sign();
        System.out.println("ECDSA Method 2 (Explicit Parameters): " +
                Base64.getEncoder().encodeToString(signed2));
    }

    private static void testElGamal() throws Exception {
        System.out.println("\n=== ElGamal Tests ===");

        // Method 1: Using low-level BC API
        ElGamalParametersGenerator paramGen = new ElGamalParametersGenerator();
        paramGen.init(1024, 12, random);
        ElGamalParameters params = paramGen.generateParameters();

        ElGamalKeyPairGenerator elGamalGen = new ElGamalKeyPairGenerator();
        ElGamalKeyGenerationParameters elGamalParams =
                new ElGamalKeyGenerationParameters(random, params);
        elGamalGen.init(elGamalParams);
        AsymmetricCipherKeyPair keyPair1 = elGamalGen.generateKeyPair();

        ElGamalEngine engine = new ElGamalEngine();
        engine.init(true, keyPair1.getPublic());
        byte[] encrypted1 = engine.processBlock(TEST_DATA_BYTES, 0, TEST_DATA_BYTES.length);
        System.out.println("ElGamal Method 1 (Low-level): " +
                Base64.getEncoder().encodeToString(encrypted1));

        // Method 2: Using JCE API
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        keyPairGen.initialize(1024);
        KeyPair keyPair2 = keyPairGen.generateKeyPair();

        Cipher cipher = Cipher.getInstance("ELGAMAL/NONE/PKCS1PADDING", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair2.getPublic());
        byte[] encrypted2 = cipher.doFinal(TEST_DATA_BYTES);
        System.out.println("ElGamal Method 2 (JCE): " +
                Base64.getEncoder().encodeToString(encrypted2));
    }

    private static void testDH() throws Exception {
        System.out.println("\n=== Diffie-Hellman Tests ===");

        // Method 1: Using low-level BC API
        DHParametersGenerator paramGen = new DHParametersGenerator();
        paramGen.init(1024, 12, random);
        DHParameters params = paramGen.generateParameters();

        DHKeyPairGenerator dhGen = new DHKeyPairGenerator();
        DHKeyGenerationParameters dhParams =
                new DHKeyGenerationParameters(random, params);
        dhGen.init(dhParams);
        AsymmetricCipherKeyPair keyPair1 = dhGen.generateKeyPair();
        System.out.println("DH Method 1 (Low-level) - Generated KeyPair: " +
                keyPair1.getPublic().toString());

        // Method 2: Using JCE API
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGen.initialize(1024);
        KeyPair keyPair2 = keyPairGen.generateKeyPair();
        System.out.println("DH Method 2 (JCE) - Public Key: " +
                Base64.getEncoder().encodeToString(keyPair2.getPublic().getEncoded()));
    }

    private static void testECDH() throws Exception {
        System.out.println("\n=== ECDH Tests ===");

        // Method 1: Using low-level BC API
        ECKeyPairGenerator ecKeyGen = new ECKeyPairGenerator();
        X9ECParameters ecParams = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256k1");
        ECDomainParameters domainParams = new ECDomainParameters(
                ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());

        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(
                domainParams, random);
        ecKeyGen.init(keyGenParams);

        AsymmetricCipherKeyPair aliceKeyPair = ecKeyGen.generateKeyPair();
        AsymmetricCipherKeyPair bobKeyPair = ecKeyGen.generateKeyPair();

        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(aliceKeyPair.getPrivate());
        BigInteger sharedSecret1 = agreement.calculateAgreement(
                bobKeyPair.getPublic());
        System.out.println("ECDH Method 1 (Low-level) - Shared Secret: " +
                sharedSecret1.toString(16));

        // Method 2: Using JCE API
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("ECDH", "BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        keyPairGen.initialize(ecSpec, random);

        KeyPair aliceKeyPair2 = keyPairGen.generateKeyPair();
        KeyPair bobKeyPair2 = keyPairGen.generateKeyPair();

        KeyAgreement agreement2 = KeyAgreement.getInstance("ECDH", "BC");
        agreement2.init(aliceKeyPair2.getPrivate());
        agreement2.doPhase(bobKeyPair2.getPublic(), true);
        byte[] sharedSecret2 = agreement2.generateSecret();
        System.out.println("ECDH Method 2 (JCE) - Shared Secret: " +
                Base64.getEncoder().encodeToString(sharedSecret2));
    }

    private static void testECGOST3410() throws Exception {
        System.out.println("\n=== ECGOST3410 Tests ===");

        // Method 1: Using GOST3410-2001 parameters
        KeyPairGenerator keyPairGen1 = KeyPairGenerator.getInstance(
                "ECGOST3410", "BC");
        keyPairGen1.initialize(new ECNamedCurveGenParameterSpec("GostR3410-2001-CryptoPro-A"));
        KeyPair keyPair1 = keyPairGen1.generateKeyPair();

        Signature signature1 = Signature.getInstance("ECGOST3410", "BC");
        signature1.initSign(keyPair1.getPrivate());
        signature1.update(TEST_DATA_BYTES);
        byte[] signed1 = signature1.sign();
        System.out.println("ECGOST3410 Method 1 (2001): " +
                Base64.getEncoder().encodeToString(signed1));

        // Method 2: Using GOST3410-2012 parameters
        KeyPairGenerator keyPairGen2 = KeyPairGenerator.getInstance(
                "ECGOST3410-2012", "BC");
        keyPairGen2.initialize(new ECNamedCurveGenParameterSpec(
                "Tc26-Gost-3410-12-512-paramSetA"));
        KeyPair keyPair2 = keyPairGen2.generateKeyPair();

        Signature signature2 = Signature.getInstance("ECGOST3410-2012-512", "BC");
        signature2.initSign(keyPair2.getPrivate());
        signature2.update(TEST_DATA_BYTES);
        byte[] signed2 = signature2.sign();
        System.out.println("ECGOST3410 Method 2 (2012): " +
                Base64.getEncoder().encodeToString(signed2));
    }

    private static void testDSTU4145() throws Exception {
        System.out.println("\n=== DSTU4145 Tests ===");

        // Method 1: JCE
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSTU4145", "BC");
        keyPairGen.initialize(new ECNamedCurveGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2.0"));
        KeyPair keyPair = keyPairGen.generateKeyPair();

        Signature signature = Signature.getInstance("DSTU4145", "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(TEST_DATA_BYTES);
        byte[] signed = signature.sign();
        System.out.println("DSTU4145 (JCE) Signature: " +
                Base64.getEncoder().encodeToString(signed));

    }

    private static void testECNR() throws Exception {
        System.out.println("\n=== ECNR Tests ===");

        // Method 1: Using low-level BC API
        ECKeyPairGenerator ecKeyGen = new ECKeyPairGenerator();
        X9ECParameters ecParams = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256k1");
        ECDomainParameters domainParams = new ECDomainParameters(
                ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());

        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(
                domainParams, random);
        ecKeyGen.init(keyGenParams);
        AsymmetricCipherKeyPair keyPair = ecKeyGen.generateKeyPair();

        ECNRSigner signer = new ECNRSigner();
        signer.init(true, keyPair.getPrivate());
        BigInteger[] signature = signer.generateSignature(TEST_DATA_BYTES);
        System.out.println("ECNR Signature (r,s): " +
                signature[0].toString(16) + ", " + signature[1].toString(16));
    }

    private static void testECMQV() throws Exception {
        System.out.println("\n=== ECMQV Tests ===");

        X9ECParameters ecP = CustomNamedCurves.getByName("secp256r1");
        ECDomainParameters domainParams = new ECDomainParameters(
                ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));

        AsymmetricCipherKeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();
        AsymmetricCipherKeyPair aliceEphemeralKeyPair = keyPairGenerator.generateKeyPair();
        AsymmetricCipherKeyPair bobKeyPair = keyPairGenerator.generateKeyPair();
        AsymmetricCipherKeyPair bobEphemeralKeyPair = keyPairGenerator.generateKeyPair();

        ECMQVBasicAgreement aliceAgreement = new ECMQVBasicAgreement();
        ECPrivateKeyParameters alicePrivateKey = (ECPrivateKeyParameters) aliceKeyPair.getPrivate();
        ECPublicKeyParameters alicePublicKey = (ECPublicKeyParameters) aliceKeyPair.getPublic();
        ECPrivateKeyParameters aliceEphemeralPrivateKey = (ECPrivateKeyParameters) aliceEphemeralKeyPair.getPrivate();
        ECPublicKeyParameters aliceEphemeralPublicKey = (ECPublicKeyParameters) aliceEphemeralKeyPair.getPublic();

        ECMQVBasicAgreement bobAgreement = new ECMQVBasicAgreement();
        ECPrivateKeyParameters bobPrivateKey = (ECPrivateKeyParameters) bobKeyPair.getPrivate();
        ECPublicKeyParameters bobPublicKey = (ECPublicKeyParameters) bobKeyPair.getPublic();
        ECPrivateKeyParameters bobEphemeralPrivateKey = (ECPrivateKeyParameters) bobEphemeralKeyPair.getPrivate();
        ECPublicKeyParameters bobEphemeralPublicKey = (ECPublicKeyParameters) bobEphemeralKeyPair.getPublic();

        ECPrivateKeyParameters alicePrivateKeyParams = new ECPrivateKeyParameters(alicePrivateKey.getD(),domainParams);
        ECPrivateKeyParameters aliceEphemeralPrivateKeyParams = new ECPrivateKeyParameters(aliceEphemeralPrivateKey.getD(),domainParams);
        ECPrivateKeyParameters bobPrivateKeyParams = new ECPrivateKeyParameters(bobPrivateKey.getD(),domainParams);
        ECPrivateKeyParameters bobEphemeralPrivateKeyParams = new ECPrivateKeyParameters(bobEphemeralPrivateKey.getD(),domainParams);

        aliceAgreement.init(new MQVPrivateParameters(alicePrivateKeyParams, aliceEphemeralPrivateKeyParams));
        bobAgreement.init(new MQVPrivateParameters(bobPrivateKeyParams, bobEphemeralPrivateKeyParams));

        ECPublicKeyParameters alicePublicKeyParams = new ECPublicKeyParameters(alicePublicKey.getQ(),domainParams);
        ECPublicKeyParameters aliceEphemeralPublicKeyParams = new ECPublicKeyParameters(aliceEphemeralPublicKey.getQ(),domainParams);
        ECPublicKeyParameters bobPublicKeyParams = new ECPublicKeyParameters(bobPublicKey.getQ(),domainParams);
        ECPublicKeyParameters bobEphemeralPublicKeyParams = new ECPublicKeyParameters(bobEphemeralPublicKey.getQ(),domainParams);

        BigInteger aliceSharedSecret = aliceAgreement.calculateAgreement(new MQVPublicParameters(bobPublicKeyParams, bobEphemeralPublicKeyParams));
        BigInteger bobSharedSecret = bobAgreement.calculateAgreement(new MQVPublicParameters(alicePublicKeyParams, aliceEphemeralPublicKeyParams));

        System.out.println("ECMQV (Low-level API) - Shared secrets match: " + aliceSharedSecret.equals(bobSharedSecret));

        // Method 2: Using JCE API
        // Note: JCE does not have built-in support for ECMQV. We'll use ECDH as an alternative.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECMQV", "BC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"), random);

        KeyPair aliceStaticKeyPair2 = keyGen.generateKeyPair();
        KeyPair aliceEphemeralKeyPair2 = keyGen.generateKeyPair();
        KeyPair bobStaticKeyPair2 = keyGen.generateKeyPair();
        KeyPair bobEphemeralKeyPair2 = keyGen.generateKeyPair();

        MQVParameterSpec aliceMQVParams = new MQVParameterSpec(
                aliceStaticKeyPair2.getPublic(),   // Alice's static public key
                aliceEphemeralKeyPair2.getPrivate(),// Alice's ephemeral private key
                aliceEphemeralKeyPair2.getPublic()  // Alice's ephemeral public key (optional)
        );

        MQVParameterSpec bobMQVParams = new MQVParameterSpec(
                bobStaticKeyPair2.getPublic(),     // Bob's static public key
                bobEphemeralKeyPair2.getPrivate(),  // Bob's ephemeral private key
                bobEphemeralKeyPair2.getPublic()    // Bob's ephemeral public key (optional)
        );

        KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECMQV", "BC");
        aliceKeyAgreement.init(aliceStaticKeyPair2.getPrivate(), aliceMQVParams);
        aliceKeyAgreement.doPhase(bobStaticKeyPair2.getPublic(), true);

        KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECMQV", "BC");
        bobKeyAgreement.init(bobStaticKeyPair2.getPrivate(), bobMQVParams);
        bobKeyAgreement.doPhase(aliceStaticKeyPair2.getPublic(), true);

        byte[] aliceSharedSecretJce = aliceKeyAgreement.generateSecret();
        byte[] bobSharedSecretJce = bobKeyAgreement.generateSecret();

        System.out.println("ECMQV (JCE API) - Shared secrets match: " + java.util.Arrays.equals(aliceSharedSecretJce, bobSharedSecretJce));
    }

    private static void testSM2() throws Exception {
        System.out.println("\n=== SM2 Tests ===");
        // Method 1: Using low-level Bouncy Castle API
        X9ECParameters ecP = CustomNamedCurves.getByName("secp256r1");
        ECDomainParameters domainParams = new ECDomainParameters(
                ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));

        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();

        SM2Engine engine = new SM2Engine();
        engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));

        byte[] TEST_DATA_BYTES = "test data".getBytes();
        byte[] ciphertext = engine.processBlock(TEST_DATA_BYTES, 0, TEST_DATA_BYTES.length);

        engine.init(false, privateKey);
        byte[] decrypted = engine.processBlock(ciphertext, 0, ciphertext.length);

        System.out.println("SM2 (Low-level API) - Decryption successful: " + new String(decrypted).equals("test data"));

        // Method 2: Using JCE API
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("sm2p256v1"), new SecureRandom());
        KeyPair jceKeyPair = keyGen.generateKeyPair();

        Cipher jceCipher = Cipher.getInstance("SM2", "BC");
        jceCipher.init(Cipher.ENCRYPT_MODE, jceKeyPair.getPublic());
        byte[] jceCiphertext = jceCipher.doFinal("test data".getBytes());

        jceCipher.init(Cipher.DECRYPT_MODE, jceKeyPair.getPrivate());
        byte[] jceDecrypted = jceCipher.doFinal(jceCiphertext);

        System.out.println("SM2 (JCE API) - Decryption successful: " + new String(jceDecrypted).equals("test data"));
    }

    private static void testMiscECC() throws Exception {
        System.out.println("\n=== MISC ECC Tests ===");
        IESCipher.ECIES test = new IESCipher.ECIES();
        IESCipher.ECIESwithAESCBC test1 = new IESCipher.ECIESwithAESCBC();
        IESCipher.ECIESwithDESedeCBC test2 = new IESCipher.ECIESwithDESedeCBC();
        IESCipher.ECIESwithSHA256 test3 = new IESCipher.ECIESwithSHA256();
        IESCipher.ECIESwithSHA256andAESCBC test4 = new IESCipher.ECIESwithSHA256andAESCBC();
        IESCipher.ECIESwithSHA256andDESedeCBC test5 = new IESCipher.ECIESwithSHA256andDESedeCBC();
        IESCipher.ECIESwithSHA384 test6 = new IESCipher.ECIESwithSHA384();
        IESCipher.ECIESwithSHA384andAESCBC test7 = new IESCipher.ECIESwithSHA384andAESCBC();
        IESCipher.ECIESwithSHA384andDESedeCBC test8 = new IESCipher.ECIESwithSHA384andDESedeCBC();
        IESCipher.ECIESwithSHA512 test9 = new IESCipher.ECIESwithSHA512();
        IESCipher.ECIESwithSHA512andAESCBC test10 = new IESCipher.ECIESwithSHA512andAESCBC();
        IESCipher.ECIESwithSHA512andDESedeCBC test11 = new IESCipher.ECIESwithSHA512andDESedeCBC();
    }
}
