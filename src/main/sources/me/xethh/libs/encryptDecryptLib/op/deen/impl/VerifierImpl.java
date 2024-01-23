package me.xethh.libs.encryptDecryptLib.op.deen.impl;

import dev.xethh.libs.toolkits.commons.encryption.RsaEncryption;
import me.xethh.libs.encryptDecryptLib.dataModel.SignedData;
import me.xethh.libs.encryptDecryptLib.op.deen.Verifier;

import java.security.PublicKey;

public class VerifierImpl implements Verifier {
    private final PublicKey publicKey;
    public VerifierImpl(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public boolean verify(SignedData signedData) {
        return RsaEncryption.verify(signedData.getData(), signedData.getSignature(), publicKey);
    }
}
