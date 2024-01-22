package me.xethh.libs.encryptDecryptLib;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.PrivateKey;

public interface Signer {
    SignedData sign(String data);
    String signToJson(String data);

    static Signer instance(PrivateKey privateKey){
        return new SignerImpl(privateKey, new ObjectMapper());
    }
    static Signer instance(PrivateKey privateKey, ObjectMapper objectMapper){
        return new SignerImpl(privateKey, objectMapper);
    }
}
