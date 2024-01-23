package me.xethh.libs.encryptDecryptLib.trust;

import lombok.Getter;

import java.security.PublicKey;
import java.util.List;

public class NameCardImpl implements NameCard{
    @Getter
    private final String name;
    @Getter
    private final String uid;
    @Getter
    private final PublicKey publicKey;
    @Getter
    private final String signature;

    @Getter
    private final List<String> trustedBy;

    @Getter
    private final String issuedBy;

    public NameCardImpl(String name, String uid, PublicKey publicKey, String signature, String issuedBy, List<String> trustedBy) {
        this.name = name;
        this.uid = uid;
        this.publicKey = publicKey;
        this.signature = signature;
        this.trustedBy = trustedBy;
        this.issuedBy = issuedBy;
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

    @Override
    public List<String> trustBy() {
        return getTrustedBy();
    }
}
