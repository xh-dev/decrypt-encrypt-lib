package me.xethh.libs.encryptDecryptLib.encryption;

import lombok.SneakyThrows;
import lombok.val;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RsaEncryption {
    public static String RSA = "RSA";
    public static String RSA_CIPHER = "RSA/ECB/PKCS1Padding";

    /**
     * Generate key pair of RSA
     *
     * @param length key size
     * @param secureRandom secure random object
     * @return KeyPair
     */
    public static KeyPair keyPair(int length, SecureRandom secureRandom) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
            generator.initialize(length, secureRandom);
            return generator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException", e);
        }
    }

    /**
     * Generate KeyPair with default key size
     *
     * @param length key size
     * @return KeyPair
     */
    public static KeyPair keyPair(int length) {
        return keyPair(length, new SecureRandom());
    }

    /**
     * Generate KeyPair with default key size
     *
     * @param secureRandom secure random object
     * @return KeyPair
     */
    public static KeyPair keyPair(SecureRandom secureRandom) {
        return keyPair(4096, secureRandom);
    }

    /**
     * Generate KeyPair with default key size and default random object
     *
     * @return KeyPair
     */
    public static KeyPair keyPair() {
        return keyPair(4096, new SecureRandom());
    }

    /**
     * Obtain Cipher object for encrypting
     *
     * @param publicKey public key
     * @return Cipher
     */
    public static Cipher encryptionCipher(PublicKey publicKey) {
        try {
            Cipher encryptCipher = Cipher.getInstance(RSA_CIPHER);
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return encryptCipher;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException", e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidKeyException", e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchPaddingException", e);
        }
    }

    /**
     * Directly encrypt plain text with public key and return as String
     *
     * @param plainText text to be encrypted
     * @param publicKey public key
     * @return
     */
    public static String encrypt(String plainText, PublicKey publicKey) {
        try {
            Cipher encryptCipher = encryptionCipher(publicKey);
            byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("BadPaddingException", e);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new RuntimeException("IllegalBlockSizeException", e);
        }
    }

    /**
     * Obtain Cipher object for decrypting
     *
     * @param privateKey private key
     * @return
     */
    public static Cipher decryptionCipher(PrivateKey privateKey) {
        try {
            Cipher decryptCipher = Cipher.getInstance(RSA_CIPHER);
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            return decryptCipher;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException", e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidKeyException", e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchPaddingException", e);
        }
    }

    /**
     * Directly decrypting cipher text to plain text
     *
     * @param cipherText encrypted message
     * @param privateKey private key
     * @return
     */
    public static String decrypt(String cipherText, PrivateKey privateKey) {
        try {
            Cipher decryptCipher = decryptionCipher(privateKey);
            byte[] bytes = Base64.getDecoder().decode(cipherText);
            return new String(decryptCipher.doFinal(bytes), UTF_8);
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("BadPaddingException", e);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new RuntimeException("IllegalBlockSizeException", e);
        }
    }

    @SneakyThrows
    public static PrivateKey getPrivateKeyFromPem(String name) {
        return getPrivateKey(RSAFormatting.loadPemBytes(name));
    }

    @SneakyThrows
    public static PrivateKey getPrivateKeyFromPemPKCS1(String data) {
        return getPrivateKeyFromPKCS1(RSAFormatting.loadPemBytes(data));
    }

    @SneakyThrows
    public static PublicKey getPubKeyFromPem(String name) {
        return getPublicKey(RSAFormatting.loadPemBytes(name));
    }

    @SneakyThrows
    public static PrivateKey getPrivateKeyFromPemString(String data) {
        return getPrivateKey(RSAFormatting.loadPemBytes(data.getBytes()));
    }

    @SneakyThrows
    public static PublicKey getPubKeyFromPemString(String data) {
        return getPublicKey(RSAFormatting.loadPemBytes(data.getBytes()));
    }

    @SneakyThrows
    public static PublicKey getPubKeyFromPemPKCS1(String data) {
        return getPublicKeyFromPKCS1(RSAFormatting.loadPemBytes(data));
    }




    /**
     * Recover PrivateKey saved in byte array format
     *
     * @param encodedKey byte array of private key data
     * @return Private Key Object
     */
    public static PrivateKey getPrivateKey(byte[] encodedKey) {
        try {
            KeyFactory factory = KeyFactory.getInstance(RSA);
            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
            return factory.generatePrivate(encodedKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException", e);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidKeySpecException", e);
        }
    }

    @SneakyThrows
    public static PrivateKey getPrivateKeyFromPKCS1(byte[] encodedKey) {
        //val algo = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
        //val info = new PrivateKeyInfo(algo, ASN1Sequence.getInstance(encodedKey));
        //KeyFactory factory = KeyFactory.getInstance(RSA);
        //PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(info.getEncoded());
        KeyFactory factory = KeyFactory.getInstance(RSA, new BouncyCastleProvider());
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        return factory.generatePrivate(encodedKeySpec);
    }

    ///**
    // * Get private key from PKCS1 format
    // *
    // * @param bytes byte array of private key data
    // * @return Private Key Object
    // */
    //public static PrivateKey getPrivateKeyFromPKCS1(byte[] bytes) {
    //    try {
    //        DerInputStream derReader = new DerInputStream(bytes);
    //        DerValue[] seq = derReader.getSequence(0);
    //        // skip version seq[0];
    //        BigInteger modulus = seq[1].getBigInteger();
    //        BigInteger publicExp = seq[2].getBigInteger();
    //        BigInteger privateExp = seq[3].getBigInteger();
    //        BigInteger prime1 = seq[4].getBigInteger();
    //        BigInteger prime2 = seq[5].getBigInteger();
    //        BigInteger exp1 = seq[6].getBigInteger();
    //        BigInteger exp2 = seq[7].getBigInteger();
    //        BigInteger crtCoef = seq[8].getBigInteger();
    //
    //        RSAPrivateCrtKeySpec keySpec =
    //                new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
    //        KeyFactory keyFactory = null;
    //        keyFactory = KeyFactory.getInstance("RSA");
    //        return keyFactory.generatePrivate(keySpec);
    //    } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
    //        e.printStackTrace();
    //        throw new RuntimeException(e);
    //    }
    //}

    /**
     * Recover PublicKey saved in byte array format
     *
     * @param encodedKey byte array of public key
     * @return Public Key Object
     */
    public static PublicKey getPublicKey(byte[] encodedKey) {
        try {
            KeyFactory factory = KeyFactory.getInstance(RSA);
            X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(encodedKey);
            return factory.generatePublic(encodedKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException", e);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidKeySpecException", e);
        }
    }

    @SneakyThrows
    public static PublicKey getPublicKeyFromPKCS1(byte[] encodedKey) {
        try {
            val algo = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
            val info = new SubjectPublicKeyInfo(algo, ASN1Sequence.getInstance(encodedKey));
            KeyFactory factory = KeyFactory.getInstance(RSA);
            X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(info.getEncoded());
            return factory.generatePublic(encodedKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException", e);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidKeySpecException", e);
        }
    }


    /**
     * Sign text with private key
     *
     * @param plainText text to be sign
     * @param privateKey private key object
     * @return Base64 Encoded signature
     */
    public static String sign(String plainText, PrivateKey privateKey) {
        try {
            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(plainText.getBytes(UTF_8));
            byte[] signature = privateSignature.sign();
            return Base64.getEncoder().encodeToString(signature);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException", e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidKeyException", e);
        } catch (SignatureException e) {
            e.printStackTrace();
            throw new RuntimeException("SignatureException", e);
        }
    }

    /**
     * Verify ciphered text by public key
     *
     * @param cipheredText encrypted message
     * @param signature signature
     * @param publicKey public key
     * @return boolean result of verification
     */
    public static boolean verify(String cipheredText, String signature, PublicKey publicKey) {
        try {
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
            publicSignature.update(cipheredText.getBytes(UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return publicSignature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException", e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidKeyException", e);
        } catch (SignatureException e) {
            e.printStackTrace();
            throw new RuntimeException("SignatureException", e);
        }
    }

    public static void main(String[] args) {
        KeyPair pair = keyPair();
        System.out.println(pair);
        System.out.println(pair.getPublic());
        System.out.println(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        String message = "Helloworld";
        System.out.println(String.format("Message %s", message));
        String encrypted = encrypt(message, getPublicKey(pair.getPublic().getEncoded()));
        String sha2Sign = sign(message, pair.getPrivate());
        System.out.println(verify(message, sha2Sign, pair.getPublic()));
        System.out.println(String.format("Encrypted Message %s", encrypted));
        String decrypted = decrypt(encrypted, getPrivateKey(pair.getPrivate().getEncoded()));
        System.out.println(String.format("Encrypted Message %s", decrypted));
        System.out.println(encrypted.equals(decrypted));
    }
}
