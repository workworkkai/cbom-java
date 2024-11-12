package com.example;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.jwt.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class NimbusJoseTest {

    // Message to be encrypt/signed
    private static final String TEST_DATA = "test data";

    private static RSAPublicKey publicKey;
    private static RSAPrivateKey privateKey;

    private final static byte[] mod = {
            (byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
            (byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226,
            (byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61,
            (byte) 48, (byte)162, (byte)206, (byte)161, (byte) 97, (byte)108, (byte)185, (byte)234,
            (byte)226, (byte)219, (byte)118, (byte)206, (byte)118, (byte)  5, (byte)169, (byte)224,

            (byte) 60, (byte)181, (byte) 90, (byte) 85, (byte) 51, (byte)123, (byte)  6, (byte)224,
            (byte)  4, (byte)122, (byte) 29, (byte)230, (byte)151, (byte) 12, (byte)244, (byte)127,
            (byte)121, (byte) 25, (byte)  4, (byte) 85, (byte)220, (byte)144, (byte)215, (byte)110,
            (byte)130, (byte) 17, (byte) 68, (byte)228, (byte)129, (byte)138, (byte)  7, (byte)130,
            (byte)231, (byte) 40, (byte)212, (byte)214, (byte) 17, (byte)179, (byte) 28, (byte)124,

            (byte)151, (byte)178, (byte)207, (byte) 20, (byte) 14, (byte)154, (byte)222, (byte)113,
            (byte)176, (byte) 24, (byte)198, (byte) 73, (byte)211, (byte)113, (byte)  9, (byte) 33,
            (byte)178, (byte) 80, (byte) 13, (byte) 25, (byte) 21, (byte) 25, (byte)153, (byte)212,
            (byte)206, (byte) 67, (byte)154, (byte)147, (byte) 70, (byte)194, (byte)192, (byte)183,
            (byte)160, (byte) 83, (byte) 98, (byte)236, (byte)175, (byte) 85, (byte) 23, (byte) 97,

            (byte) 75, (byte)199, (byte)177, (byte) 73, (byte)145, (byte) 50, (byte)253, (byte)206,
            (byte) 32, (byte)179, (byte)254, (byte)236, (byte)190, (byte) 82, (byte) 73, (byte) 67,
            (byte)129, (byte)253, (byte)252, (byte)220, (byte)108, (byte)136, (byte)138, (byte) 11,
            (byte)192, (byte)  1, (byte) 36, (byte)239, (byte)228, (byte) 55, (byte) 81, (byte)113,
            (byte) 17, (byte) 25, (byte)140, (byte) 63, (byte)239, (byte)146, (byte)  3, (byte)172,

            (byte) 96, (byte) 60, (byte)227, (byte)233, (byte) 64, (byte)255, (byte)224, (byte)173,
            (byte)225, (byte)228, (byte)229, (byte) 92, (byte)112, (byte) 72, (byte) 99, (byte) 97,
            (byte) 26, (byte) 87, (byte)187, (byte)123, (byte) 46, (byte) 50, (byte) 90, (byte)202,
            (byte)117, (byte) 73, (byte) 10, (byte)153, (byte) 47, (byte)224, (byte)178, (byte)163,
            (byte) 77, (byte) 48, (byte) 46, (byte)154, (byte) 33, (byte)148, (byte) 34, (byte)228,

            (byte) 33, (byte)172, (byte)216, (byte) 89, (byte) 46, (byte)225, (byte)127, (byte) 68,
            (byte)146, (byte)234, (byte) 30, (byte)147, (byte) 54, (byte)146, (byte)  5, (byte)133,
            (byte) 45, (byte) 78, (byte)254, (byte) 85, (byte) 55, (byte) 75, (byte)213, (byte) 86,
            (byte)194, (byte)218, (byte)215, (byte)163, (byte)189, (byte)194, (byte) 54, (byte)  6,
            (byte) 83, (byte) 36, (byte) 18, (byte)153, (byte) 53, (byte)  7, (byte) 48, (byte) 89,

            (byte) 35, (byte) 66, (byte)144, (byte)  7, (byte) 65, (byte)154, (byte) 13, (byte) 97,
            (byte) 75, (byte) 55, (byte)230, (byte)132, (byte)  3, (byte) 13, (byte)239, (byte) 71  };


    private static final byte[] exp= { 1, 0, 1 };


    private static final byte[] modPriv = {
            (byte) 84, (byte) 80, (byte)150, (byte) 58, (byte)165, (byte)235, (byte)242, (byte)123,
            (byte)217, (byte) 55, (byte) 38, (byte)154, (byte) 36, (byte)181, (byte)221, (byte)156,
            (byte)211, (byte)215, (byte)100, (byte)164, (byte) 90, (byte) 88, (byte) 40, (byte)228,
            (byte) 83, (byte)148, (byte) 54, (byte)122, (byte)  4, (byte) 16, (byte)165, (byte) 48,
            (byte) 76, (byte)194, (byte) 26, (byte)107, (byte) 51, (byte) 53, (byte)179, (byte)165,

            (byte) 31, (byte) 18, (byte)198, (byte)173, (byte) 78, (byte) 61, (byte) 56, (byte) 97,
            (byte)252, (byte)158, (byte)140, (byte) 80, (byte) 63, (byte) 25, (byte)223, (byte)156,
            (byte) 36, (byte)203, (byte)214, (byte)252, (byte)120, (byte) 67, (byte)180, (byte)167,
            (byte)  3, (byte) 82, (byte)243, (byte) 25, (byte) 97, (byte)214, (byte) 83, (byte)133,
            (byte) 69, (byte) 16, (byte)104, (byte) 54, (byte)160, (byte)200, (byte) 41, (byte) 83,

            (byte)164, (byte)187, (byte) 70, (byte)153, (byte)111, (byte)234, (byte)242, (byte)158,
            (byte)175, (byte) 28, (byte)198, (byte) 48, (byte)211, (byte) 45, (byte)148, (byte) 58,
            (byte) 23, (byte) 62, (byte)227, (byte) 74, (byte) 52, (byte)117, (byte) 42, (byte) 90,
            (byte) 41, (byte)249, (byte)130, (byte)154, (byte) 80, (byte)119, (byte) 61, (byte) 26,
            (byte)193, (byte) 40, (byte)125, (byte) 10, (byte)152, (byte)174, (byte)227, (byte)225,

            (byte)205, (byte) 32, (byte) 62, (byte) 66, (byte)  6, (byte)163, (byte)100, (byte) 99,
            (byte)219, (byte) 19, (byte)253, (byte) 25, (byte)105, (byte) 80, (byte)201, (byte) 29,
            (byte)252, (byte)157, (byte)237, (byte) 69, (byte)  1, (byte) 80, (byte)171, (byte)167,
            (byte) 20, (byte)196, (byte)156, (byte)109, (byte)249, (byte) 88, (byte)  0, (byte)  3,
            (byte)152, (byte) 38, (byte)165, (byte) 72, (byte) 87, (byte)  6, (byte)152, (byte) 71,

            (byte)156, (byte)214, (byte) 16, (byte) 71, (byte) 30, (byte) 82, (byte) 51, (byte)103,
            (byte) 76, (byte)218, (byte) 63, (byte)  9, (byte) 84, (byte)163, (byte)249, (byte) 91,
            (byte)215, (byte) 44, (byte)238, (byte) 85, (byte)101, (byte)240, (byte)148, (byte)  1,
            (byte) 82, (byte)224, (byte) 91, (byte)135, (byte)105, (byte)127, (byte) 84, (byte)171,
            (byte)181, (byte)152, (byte)210, (byte)183, (byte)126, (byte) 24, (byte) 46, (byte)196,

            (byte) 90, (byte)173, (byte) 38, (byte)245, (byte)219, (byte)186, (byte)222, (byte) 27,
            (byte)240, (byte)212, (byte)194, (byte) 15, (byte) 66, (byte)135, (byte)226, (byte)178,
            (byte)190, (byte) 52, (byte)245, (byte) 74, (byte) 65, (byte)224, (byte) 81, (byte)100,
            (byte) 85, (byte) 25, (byte)204, (byte)165, (byte)203, (byte)187, (byte)175, (byte) 84,
            (byte)100, (byte) 82, (byte) 15, (byte) 11, (byte) 23, (byte)202, (byte)151, (byte)107,

            (byte) 54, (byte) 41, (byte)207, (byte)  3, (byte)136, (byte)229, (byte)134, (byte)131,
            (byte) 93, (byte)139, (byte) 50, (byte)182, (byte)204, (byte) 93, (byte)130, (byte)89   };

    protected static void testAllNimbusJose() throws Exception {
        testNimbusJWSRSA();
        testNimbusJWSEC();
        testJWSEdDSA();
        testJWTRSA();
        testJWTRSAEncrypt();
        testJWTEC();
        testJWTEdDSA();
    }

    private static void testNimbusJWSRSA() throws Exception {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

        // Prepare JWS object with simple string as payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
                new Payload(TEST_DATA));

        // Compute the RSA signature
        jwsObject.sign(signer);

        String s = jwsObject.serialize();

        // To parse the JWS and verify it, e.g. on client-side
        jwsObject = JWSObject.parse(s);

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);

        assertTrue(jwsObject.verify(verifier));

        assertEquals(TEST_DATA, jwsObject.getPayload().toString());
    }

    private static void testNimbusJWSEC() throws Exception {
        // Generate an EC key pair
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("123")
                .generate();
        ECKey ecPublicJWK = ecJWK.toPublicJWK();

        // Create the EC signer
        JWSSigner signer = new ECDSASigner(ecJWK);

        // Creates the JWS object with payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecJWK.getKeyID()).build(),
                new Payload(TEST_DATA));

        // Compute the EC signature
        jwsObject.sign(signer);

        // Serialize the JWS to compact form
        String s = jwsObject.serialize();


        // The recipient creates a verifier with the public EC key
        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);

        // Verify the EC signature
        assertTrue("ES256 signature verified", jwsObject.verify(verifier));
        assertEquals(TEST_DATA, jwsObject.getPayload().toString());
    }

    private static void testJWSEdDSA() throws Exception {
        // Generate a key pair with Ed25519 curve
        OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("123")
                .generate();
        OctetKeyPair publicJWK = jwk.toPublicJWK();

        // Create the EdDSA signer
        JWSSigner signer = new Ed25519Signer(jwk);

        // Creates the JWS object with payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.getKeyID()).build(),
                new Payload(TEST_DATA));

        // Compute the EdDSA signature
        jwsObject.sign(signer);

        // Serialize the JWS to compact form
        String s = jwsObject.serialize();


        // The recipient creates a verifier with the public EdDSA key
        JWSVerifier verifier = new Ed25519Verifier(publicJWK);

        // Verify the EdDSA signature
        assertTrue("Ed25519 signature verified", jwsObject.verify(verifier));
        assertEquals(TEST_DATA, jwsObject.getPayload().toString());
    }

    private static void testJWTRSA() throws Exception {
        // RSA signatures require a public and private RSA key pair, the public key
        // must be made known to the JWS recipient in order to verify the signatures
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("https://c2id.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        String s = signedJWT.serialize();

        // On the consumer side, parse the JWS and verify its RSA signature
        signedJWT = SignedJWT.parse(s);

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
        assertTrue(signedJWT.verify(verifier));

        // Retrieve / verify the JWT claims according to the app requirements
        assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("https://c2id.com", signedJWT.getJWTClaimsSet().getIssuer());
        assertTrue(new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

    private static void testJWTRSAEncrypt() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(1, mod), new BigInteger(1, exp));
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(1, mod), new BigInteger(1, modPriv));

        publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        // Compose the JWT claims set
        Date now = new Date();

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .issuer("https://openid.net")
                .subject("alice")
                .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                .expirationTime(new Date(now.getTime() + 1000*60*10)) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .build();

        System.out.println(jwtClaims.toJSONObject());

        // Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
        JWEHeader header = new JWEHeader(
                JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A128GCM
        );

        // Create the encrypted JWT object
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

        // Create an encrypter with the specified public RSA key
        RSAEncrypter encrypter = new RSAEncrypter(publicKey);

        // Do the actual encryption
        jwt.encrypt(encrypter);

        // Serialise to JWT compact form
        String jwtString = jwt.serialize();

        System.out.println(jwtString);

        // Parse
        jwt = EncryptedJWT.parse(jwtString);

        // Create a decrypter with the specified private RSA key
        RSADecrypter decrypter = new RSADecrypter(privateKey);

        // Decrypt
        jwt.decrypt(decrypter);

        // Retrieve JWT claims
        System.out.println(jwt.getJWTClaimsSet().getIssuer());;
        System.out.println(jwt.getJWTClaimsSet().getSubject());
        System.out.println(jwt.getJWTClaimsSet().getAudience().size());
        System.out.println(jwt.getJWTClaimsSet().getExpirationTime());
        System.out.println(jwt.getJWTClaimsSet().getNotBeforeTime());
        System.out.println(jwt.getJWTClaimsSet().getIssueTime());
        System.out.println(jwt.getJWTClaimsSet().getJWTID());
    }

    private static void testJWTEC() throws Exception {
        // Generate an EC key pair
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("123")
                .generate();
        ECKey ecPublicJWK = ecJWK.toPublicJWK();

        // Create the EC signer
        JWSSigner signer = new ECDSASigner(ecJWK);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("https://c2id.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecJWK.getKeyID()).build(),
                claimsSet);

        // Compute the EC signature
        signedJWT.sign(signer);

        // Serialize the JWS to compact form
        String s = signedJWT.serialize();

        // On the consumer side, parse the JWS and verify its EC signature
        signedJWT = SignedJWT.parse(s);

        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);
        assertTrue(signedJWT.verify(verifier));

        // Retrieve / verify the JWT claims according to the app requirements
        assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("https://c2id.com", signedJWT.getJWTClaimsSet().getIssuer());
        assertTrue(new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

    private static void testJWTEdDSA() throws Exception {
        // Generate a key pair with Ed25519 curve
        OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("123")
                .generate();
        OctetKeyPair publicJWK = jwk.toPublicJWK();

        // Create the EdDSA signer
        JWSSigner signer = new Ed25519Signer(jwk);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("https://c2id.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.getKeyID()).build(),
                claimsSet);

        // Compute the EC signature
        signedJWT.sign(signer);

        // Serialize the JWS to compact form
        String s = signedJWT.serialize();

        // On the consumer side, parse the JWS and verify its EdDSA signature
        signedJWT = SignedJWT.parse(s);

        JWSVerifier verifier = new Ed25519Verifier(publicJWK);
        assertTrue(signedJWT.verify(verifier));

        // Retrieve / verify the JWT claims according to the app requirements
        assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
        assertEquals("https://c2id.com", signedJWT.getJWTClaimsSet().getIssuer());
        assertTrue(new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

}
