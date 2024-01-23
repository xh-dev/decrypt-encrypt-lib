package me.xethh.libs.encryptDecryptLib.op.signing;

import me.xethh.libs.encryptDecryptLib.dataModel.SignedData;

import java.security.PublicKey;

public interface Verifier {
    boolean verify(SignedData signedData);

    static Verifier instance(PublicKey publicKey){
        return new VerifierImpl(publicKey);
    }
}
