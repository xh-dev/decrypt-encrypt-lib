package me.xethh.libs.encryptDecryptLib.encryption;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

public class Digest {
    public static void digestStream(InputStream is, MessageDigest digest, int byteSize){
        byte[] b = new byte[byteSize];
        try {
            while (is.read(b) != -1){
                digest.update(b);
            }
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
