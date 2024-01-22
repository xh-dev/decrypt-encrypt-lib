package me.xethh.libs.encryptDecryptLib;

import java.security.PublicKey;

public interface Verifier {
    boolean verify(SignedData signedData);

    static Verifier instance(PublicKey publicKey){
        return new VerifierImpl(publicKey);
    }
}
