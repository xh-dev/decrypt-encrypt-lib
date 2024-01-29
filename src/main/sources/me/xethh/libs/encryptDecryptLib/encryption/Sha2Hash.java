package me.xethh.libs.encryptDecryptLib.encryption;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Sha2Hash {
    public static String SHA2 = "SHA-512";
    public static byte[] hashBytes(byte[] bytes){
        return hash(bytes);
    }
    public static String hashBytes64(byte[] bytes){
        return hashBase64(bytes);
    }
    public static String hashBytesHex(byte[] bytes){
        return hashHex(bytes);
    }
    public static MessageDigest digest(){
        try {
            return MessageDigest.getInstance(SHA2);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage(), e);
        }

    }
    public static byte[] hash(byte[]... bytes){
        MessageDigest digest = digest();
        for(int i=0;i<bytes.length;i++)
            Digest.digestStream(new ByteArrayInputStream(bytes[i]),digest, 512);
        return digest.digest();
    }

    public static String hashHex(byte[]... bytes){
        return Hex.toHexString(hash(bytes));
    }
    public static String hashBase64(byte[]... bytes){
        return Base64.getEncoder().encodeToString(hash(bytes));
    }

}
