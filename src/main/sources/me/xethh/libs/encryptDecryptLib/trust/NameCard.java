package me.xethh.libs.encryptDecryptLib.trust;

import java.security.PublicKey;

public interface NameCard {
    String name();
    String uid();
    PublicKey publicKey();
    String signature();

    static NameCard instance(String name, String uid, PublicKey publicKey, String signature){
        return new NameCardImpl(name, uid, publicKey, signature);
    }
}
