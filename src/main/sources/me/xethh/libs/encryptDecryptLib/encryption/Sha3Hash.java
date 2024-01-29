package me.xethh.libs.encryptDecryptLib.encryption;

import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.util.Base64;

public class Sha3Hash {
    public static byte[] hashBytes(byte[] bytes){
        return hash(bytes);
    }
    public static String hashBytes64(byte[] bytes){
        return hashBase64(bytes);
    }
    public static String hashBytesHex(byte[] bytes){
        return hashHex(bytes);
    }
    public static SHA3.Digest512 digest(){
        return new SHA3.Digest512();
    }
    public static byte[] hash(byte[]... bytes){
        SHA3.Digest512 digest = digest();
        for(int i=0; i<bytes.length; i++)
            Digest.digestStream(new ByteArrayInputStream(bytes[i]), digest,512);
        return digest.digest();
    }
    public static String hashHex(byte[]... bytes){
        return Hex.toHexString(hash(bytes));
    }
    public static String hashBase64(byte[]... bytes){
        return Base64.getEncoder().encodeToString(hash(bytes));
    }
}
