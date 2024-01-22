package me.xethh.libs.encryptDecryptLib;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.var;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

public interface DeEnCryptor {
    static DeEnCryptorImpl of(PublicKey publicKey, PrivateKey privateKey) {
        var om = new ObjectMapper();
        return DeEnCryptor.of(publicKey, privateKey, om);
    }

    static DeEnCryptorImpl of(PublicKey publicKey, PrivateKey privateKey, ObjectMapper om) {
        return new DeEnCryptorImpl(publicKey, privateKey, om);
    }

    /**
     * Wrapping the method {@link me.xethh.libs.encryptDecryptLib.DeEnCryptor#encryptToContainer(PublicKey, String)} by serializing the output into json string
     */
    String encryptToJsonContainer(PublicKey receiver, String data);

    /**
     * Encrypt an input string into {@link me.xethh.libs.encryptDecryptLib.Envelope} object
     * @param receiver public key of the receiver
     * @param data data to be encrypted in string format
     * @return {@link me.xethh.libs.encryptDecryptLib.Envelope}
     */
    DataContainer encryptToContainer(PublicKey receiver, String data);

    /**
     * Encrypting an java object into json format and then return as {@link me.xethh.libs.encryptDecryptLib.Envelope} object
     *
     * @param receiver public key of the receiver
     * @param in       input data object
     * @param <O>      generic of the input data
     * @return {@link me.xethh.libs.encryptDecryptLib.Envelope}
     */
    <O> DataContainer encryptObjectToContainer(PublicKey receiver, O in);

    <O> String encryptObjectToJsonContainer(PublicKey receiver, O in);


    Optional<String> decryptContainer(PublicKey receiver, DataContainer dataContainer);

    Optional<String> decryptJsonContainer(PublicKey receiver, String data);
}
