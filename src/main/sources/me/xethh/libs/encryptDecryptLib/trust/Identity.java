package me.xethh.libs.encryptDecryptLib.trust;

import com.fasterxml.jackson.databind.ObjectMapper;
import me.xethh.libs.encryptDecryptLib.op.deen.DeEnCryptor;
import me.xethh.libs.encryptDecryptLib.op.signing.Signer;
import me.xethh.libs.encryptDecryptLib.op.signing.Verifier;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface Identity {
    String uid();

    String name();

    PublicKey publicKey();

    String fingerPrint();

    Signer signer();

    Verifier verifier();

    DeEnCryptor deenCryptor();

    NameCard mySelf();


    static Identity instance(String name) {
        return new IdentityImpl(name);
    }

    static Identity instance(String name, ObjectMapper mapper) {
        return new IdentityImpl(name, mapper);
    }

    static Identity instance(PublicKey publicKey, PrivateKey privateKey, String uid, String name, String salt, String fingerPrint) {
        return new IdentityImpl(publicKey, privateKey, uid, name, salt, fingerPrint, new ObjectMapper());
    }

    static Identity instance(PublicKey publicKey, PrivateKey privateKey, String uid, String name, String salt, String fingerPrint, ObjectMapper mapper) {
        return new IdentityImpl(publicKey, privateKey, uid, name, salt, fingerPrint, mapper);
    }
}
