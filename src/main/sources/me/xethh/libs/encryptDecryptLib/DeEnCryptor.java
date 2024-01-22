package me.xethh.libs.encryptDecryptLib;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.val;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

public interface DeEnCryptor {
    static DeEnCryptorImpl of(PublicKey publicKey, PrivateKey privateKey) {
        val om = new ObjectMapper();
        return DeEnCryptor.of(publicKey, privateKey, om);
    }

    static DeEnCryptorImpl of(PublicKey publicKey, PrivateKey privateKey, ObjectMapper om) {
        return new DeEnCryptorImpl(publicKey, privateKey, om);
    }

    /**
     * Wrapping the method {@link me.xethh.libs.encryptDecryptLib.DeEnCryptor#encryptToContainer(PublicKey, String)} by serializing the output into json string
     */
    String encryptToJsonContainer(PublicKey receiver, String data);

    DataContainer encryptToContainer(PublicKey receiver, String data);

    <O> DataContainer encryptObjectToContainer(PublicKey receiver, O in);

    <O> String encryptObjectToJsonContainer(PublicKey receiver, O in);


    Optional<String> decryptContainer(PublicKey receiver, DataContainer dataContainer);

    Optional<String> decryptJsonContainer(PublicKey receiver, String data);
}
