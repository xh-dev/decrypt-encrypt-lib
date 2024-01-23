package me.xethh.libs.encryptDecryptLib.trust;

import lombok.Getter;

import java.security.PublicKey;

public class NameCardImpl implements NameCard{
    @Getter
    private final String name;
    @Getter
    private final String uid;
    @Getter
    private final PublicKey publicKey;
    @Getter
    private final String signature;

    public NameCardImpl(String name, String uid, PublicKey publicKey, String signature) {
        this.name = name;
        this.uid = uid;
        this.publicKey = publicKey;
        this.signature = signature;
    }

    @Override
    public String name() {
        return getName();
    }

    @Override
    public String uid() {
        return getUid();
    }

    @Override
    public PublicKey publicKey() {
        return getPublicKey();
    }

    @Override
    public String signature() {
        return getSignature();
    }
}
