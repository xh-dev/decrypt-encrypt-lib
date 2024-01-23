package me.xethh.libs.encryptDecryptLib.op.signing;

import dev.xethh.libs.toolkits.commons.encryption.RsaEncryption;
import me.xethh.libs.encryptDecryptLib.dataModel.SignedData;

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
