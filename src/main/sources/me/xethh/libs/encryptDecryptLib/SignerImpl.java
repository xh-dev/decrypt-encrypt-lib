package me.xethh.libs.encryptDecryptLib;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.xethh.libs.toolkits.commons.encryption.RsaEncryption;
import lombok.SneakyThrows;
import lombok.val;

import java.security.PrivateKey;

public class SignerImpl implements Signer{
    private final PrivateKey privateKey;
    private final ObjectMapper objectMapper;
    public SignerImpl(PrivateKey privateKey, ObjectMapper objectMapper) {
        this.privateKey = privateKey;
        this.objectMapper = objectMapper;
    }

    @Override
    public SignedData sign(String data) {
        val signature = RsaEncryption.sign(data, privateKey);
        return SignedData.builder()
                .data(data)
                .signature(signature)
                .build();
    }

    @Override
    @SneakyThrows
    public String signToJson(String data) {
        return objectMapper.writeValueAsString(sign(data));

    }
}
