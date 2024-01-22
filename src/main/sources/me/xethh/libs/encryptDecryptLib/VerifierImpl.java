package me.xethh.libs.encryptDecryptLib;

import dev.xethh.libs.toolkits.commons.encryption.RsaEncryption;
import lombok.val;

import java.security.PrivateKey;
import java.security.PublicKey;

public class VerifierImpl implements Verifier{
    private final PublicKey publicKey;
    public VerifierImpl(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public boolean verify(SignedData signedData) {
        return RsaEncryption.verify(signedData.getData(), signedData.getSignature(), publicKey);
    }
}
