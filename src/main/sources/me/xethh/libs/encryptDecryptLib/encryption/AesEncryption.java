package me.xethh.libs.encryptDecryptLib.encryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AesEncryption {
    public static SecretKey secretKey(){
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException",e);
        }
    }
    public static SecretKey secretKey(byte[] bytes){
        return new SecretKeySpec(bytes, 0, bytes.length, "AES");
    }
    public static IvParameterSpec iv(){
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    public static IvParameterSpec iv(byte[] iv){
        return new IvParameterSpec(iv);
    }

    public static Cipher encryptionCipher(SecretKey secretKey, IvParameterSpec iv){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            return cipher;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException",e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchPaddingException",e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidKeyException",e);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidAlgorithmParameterException",e);
        }
    }

    public static String encrypt(String msg, SecretKey secretKey, IvParameterSpec iv){
        try {
            return Base64.getEncoder().encodeToString(encryptionCipher(secretKey, iv).doFinal(msg.getBytes(UTF_8)));
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("BadPaddingException",e);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new RuntimeException("IllegalBlockSizeException",e);
        }
    }

    public static Cipher decryptionCipher(SecretKey secretKey, IvParameterSpec  iv){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            return cipher;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchAlgorithmException",e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("NoSuchPaddingException",e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidKeyException",e);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException("InvalidAlgorithmParameterException",e);
        }
    }
    public static String decrypt(String msg, SecretKey secretKey, IvParameterSpec  iv){
        try {
            return new String(decryptionCipher(secretKey, iv).doFinal(Base64.getDecoder().decode(msg)),UTF_8);
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException("BadPaddingException",e);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new RuntimeException("IllegalBlockSizeException",e);
        }
    }

    public static String sign(SecretKey key, IvParameterSpec iv, String supplier){
        return Sha3Hash.hashBase64(key.getEncoded(), iv.getIV(), supplier.getBytes());
    }
    public static boolean verify(SecretKey key, IvParameterSpec iv, String supplier, String sign){
        return sign.equals(sign(key,iv,supplier));
    }

    public static void main(String[] args){
        IvParameterSpec iv = iv();
        SecretKey key = secretKey();
        System.out.println(key);
        System.out.println(iv);
        String encrypted = encrypt("helloworld", secretKey(key.getEncoded()), iv);
        System.out.println(encrypted);
        String signed = sign(secretKey(key.getEncoded()), iv(iv.getIV()), "helloworld");
        System.out.println(signed);
        System.out.println(verify(secretKey(key.getEncoded()), iv(iv.getIV()), "helloworld", signed));
        String decrypted = decrypt(encrypted, secretKey(key.getEncoded()), iv);
        System.out.println(decrypted);
    }

}
