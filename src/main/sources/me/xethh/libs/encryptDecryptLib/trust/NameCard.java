package me.xethh.libs.encryptDecryptLib.trust;

import java.security.PublicKey;
import java.util.List;

public interface NameCard {
    String name();
    String uid();
    PublicKey publicKey();
    String signature();

    String issueBy();

    List<String> trustBy();

    static NameCard instance(String name, String uid, PublicKey publicKey, String signature, String issuedBy, List<String> trustedBy){
        return new NameCardImpl(name, uid, publicKey, signature, issuedBy, trustedBy);
    }
}
