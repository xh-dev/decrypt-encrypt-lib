package me.xeth.libs.encryptDecryptLib;

import java.security.PublicKey;

public class Bernice {
    private final PublicKey publicKey;
    public Bernice(PublicKey publicKey){
        this.publicKey = publicKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public static Bernice of(PublicKey publicKey){
        return new Bernice(publicKey);
    }
}
