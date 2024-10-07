package com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.OutputStream;
import java.net.InetAddress;
import java.security.*;
import java.security.spec.*;
import javax.net.ssl.*;
import java.util.Base64;

public class cryptoAssetDetectionTest {

    public static void main(String[] args) {
        try {
            testBouncyCastleAES();
            testJCARSA();
            testSSLSocket();
            testAESWithDifferentModes();
            testEllipticCurveCrypto();
            testMessageDigest();
            testSecureRandom();
            testHMAC();
            testPBKDF2();
            testDSA();

            testObfuscated();
            testStringLiterals();
            testDynamicMethodInvocation();
            testCustomWrapper();
            testComments();
            testUnusedImports();
            testNonCryptoSimilarNames();

            testRSAWithDifferentKeySizes();
            testAdditionalEllipticCurves();
            testAdditionalHashFunctions();
            testChaCha20Poly1305();
            testDifferentSSLTLSProtocols();
            testWeakAlgorithms();

            System.out.println("All cryptographic tests completed.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Original test methods
    public static void testBouncyCastleAES() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        SecretKey key = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal("test".getBytes());
        System.out.println("BouncyCastle AES Encrypted: " + Base64.getEncoder().encodeToString(ciphertext));
    }

    public static void testJCARSA() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = keyGen.generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        byte[] ciphertext = cipher.doFinal("test".getBytes());
        System.out.println("JCA RSA Encrypted: " + Base64.getEncoder().encodeToString(ciphertext));
    }

    public static void testSSLSocket() {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(InetAddress.getByName("google.com"),
                    443);
            socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            socket.setEnabledCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
            OutputStream out = socket.getOutputStream();
            out.write("test".getBytes());
            out.flush();
            socket.close();
            System.out.println("SSLSocket test completed.");
        } catch (Exception e) {
            System.err.println("SSLSocket test failed: " + e.getMessage());
        }
    }

    public static void testAESWithDifferentModes() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ciphertext = cipher.doFinal("test".getBytes());
        System.out.println("AES-CBC-256 Encrypted: " + Base64.getEncoder().encodeToString(ciphertext));
    }

    public static void testEllipticCurveCrypto() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(keyPair.getPrivate());
        ecdsa.update("test".getBytes());
        byte[] signature = ecdsa.sign();
        System.out.println("ECDSA Signature: " + Base64.getEncoder().encodeToString(signature));
    }

    public static void testMessageDigest() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest("test".getBytes());
        System.out.println("SHA-256 Digest: " + Base64.getEncoder().encodeToString(digest));
    }

    public static void testSecureRandom() throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] randomBytes = new byte[16];
        random.nextBytes(randomBytes);
        System.out.println("SecureRandom bytes: " + Base64.getEncoder().encodeToString(randomBytes));
    }

    public static void testHMAC() throws Exception {
        Key key = new SecretKeySpec("secret".getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] result = mac.doFinal("test".getBytes());
        System.out.println("HMAC-SHA256: " + Base64.getEncoder().encodeToString(result));
    }

    public static void testPBKDF2() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] salt = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(salt);
        KeySpec spec = new PBEKeySpec("password".toCharArray(), salt, 65536, 256);
        SecretKey key = factory.generateSecret(spec);
        System.out.println("PBKDF2 Key: " + Base64.getEncoder().encodeToString(key.getEncoded()));
    }

    public static void testDSA() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(pair.getPrivate());
        dsa.update("test".getBytes());
        byte[] signature = dsa.sign();
        System.out.println("DSA Signature: " + Base64.getEncoder().encodeToString(signature));
    }

    public static void testObfuscated() throws Exception{
        String[] encodedData = {"QUVT", "QUVTL0VDQi9QS0NTNVBhZGRpbmc=", "T2JmdXNjYXRlZCBBRVM6IA==", "dGVzdA=="};

        // Decoding the Base64 strings into usable data
        byte[] algorithm = Base64.getDecoder().decode(encodedData[0]); // "AES"
        byte[] cipherTransformation = Base64.getDecoder().decode(encodedData[1]); // "AES/ECB/PKCS5Padding"
        byte[] prefixMessage = Base64.getDecoder().decode(encodedData[2]); // "Obfuscated AES: "
        byte[] plainText = Base64.getDecoder().decode(encodedData[3]); // "test"

        // Setting up the KeyGenerator, Cipher, and SecretKey for AES encryption
        KeyGenerator keyGenerator = KeyGenerator.getInstance(new String(algorithm));
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance(new String(cipherTransformation));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        // Performing encryption
        byte[] encryptedText = cipher.doFinal(plainText);
        // Printing the result as Base64 encoded ciphertext
        System.out.println(new String(prefixMessage) + Base64.getEncoder().encodeToString(encryptedText));
    }


    public static void testStringLiterals() {
        String algorithm = "AES/ECB/PKCS5Padding";
        System.out.println("Algorithm in string literal: " + algorithm);
    }

    public static void testDynamicMethodInvocation() throws Exception {
        String className = "javax.crypto.Cipher";
        String methodName = "getInstance";
        Class<?> clazz = Class.forName(className);
        java.lang.reflect.Method method = clazz.getMethod(methodName, String.class);
        Object cipher = method.invoke(null, "AES/ECB/PKCS5Padding");
        System.out.println("Dynamic invocation: " + cipher.getClass().getName());
    }

    private static class CustomCrypto {
        public static byte[] encrypt(String data) throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecretKey key = keyGen.generateKey();
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data.getBytes());
        }
    }

    public static void testCustomWrapper() throws Exception {
        byte[] encrypted = CustomCrypto.encrypt("test");
        System.out.println("Custom wrapper: " + Base64.getEncoder().encodeToString(encrypted));
    }

    public static void testComments() {
        // This method uses AES encryption
        System.out.println("Method with crypto comment");
    }

    // import javax.crypto.BadPaddingException;
    // import javax.crypto.IllegalBlockSizeException;
    public static void testUnusedImports() {
        System.out.println("Method with unused crypto imports");
    }

    public static void testNonCryptoSimilarNames() {
        String aesThetic = "beautiful";
        String cipherText = "encoded text";
        System.out.println("Non-crypto similar names: " + aesThetic + ", " + cipherText);
    }

    // Additional requested test methods
    public static void testRSAWithDifferentKeySizes() throws Exception {
        for (int keySize : new int[]{2048, 3072, 4096}) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize);
            KeyPair pair = keyGen.generateKeyPair();
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
            byte[] ciphertext = cipher.doFinal("test".getBytes());
            System.out.println("RSA-" + keySize + " Encrypted: " + Base64.getEncoder().encodeToString(ciphertext));
        }
    }

    public static void testAdditionalEllipticCurves() throws Exception {
        for (String curve : new String[]{"secp384r1", "secp256r1"}) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);
            keyGen.initialize(ecSpec);
            KeyPair keyPair = keyGen.generateKeyPair();
            // Use SHA-384 for secp384r1 and SHA-256 for secp256r1
            String algorithm = curve.equals("secp384r1") ? "SHA384withECDSA" : "SHA256withECDSA";
            Signature ecdsa = Signature.getInstance(algorithm);
            ecdsa.initSign(keyPair.getPrivate());
            ecdsa.update("test".getBytes());
            byte[] signature = ecdsa.sign();
            System.out.println("ECDSA (" + curve + ") using " + algorithm + " Signature: " + Base64.getEncoder().encodeToString(signature));
        }
    }

    public static void testAdditionalHashFunctions() throws Exception {
        for (String hashAlgo : new String[]{"SHA3-256", "SHA-512"}) {
            MessageDigest md = MessageDigest.getInstance(hashAlgo);
            byte[] digest = md.digest("test".getBytes());
            System.out.println(hashAlgo + " Digest: " + Base64.getEncoder().encodeToString(digest));
        }
    }

    public static void testChaCha20Poly1305() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
        SecretKey key = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
        byte[] ciphertext = cipher.doFinal("test".getBytes());
        System.out.println("ChaCha20-Poly1305 Encrypted: " + Base64.getEncoder().encodeToString(ciphertext));
    }

    public static void testDifferentSSLTLSProtocols() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);
        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        String[] protocols = socket.getSupportedProtocols();
        System.out.println("Supported SSL/TLS protocols: " + String.join(", ", protocols));
    }

    public static void testWeakAlgorithms() throws Exception {
        // MD5 (weak hash function)
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] md5Digest = md5.digest("test".getBytes());
        System.out.println("MD5 Digest (weak): " + Base64.getEncoder().encodeToString(md5Digest));

        // DES (weak encryption)
        KeyGenerator desKeyGen = KeyGenerator.getInstance("DES");
        SecretKey desKey = desKeyGen.generateKey();
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        desCipher.init(Cipher.ENCRYPT_MODE, desKey);
        byte[] desCiphertext = desCipher.doFinal("test".getBytes());
        System.out.println("DES Encrypted (weak): " + Base64.getEncoder().encodeToString(desCiphertext));
    }
}