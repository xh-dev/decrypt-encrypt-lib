package me.xethh.libs.encryptDecryptLib.op.signing;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.val;
import me.xethh.libs.encryptDecryptLib.dataModel.SignedData;
import me.xethh.libs.encryptDecryptLib.encryption.RsaEncryption;

import java.security.PrivateKey;

public class SignerImpl implements Signer {
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
    public SignedData signMultiple(String... data) {
        val sb = new StringBuilder();
        for(String d : data){
            sb.append(d);
        }
        return sign(sb.toString());
    }

    @Override
    @SneakyThrows
    public String signToJson(String data) {
        return objectMapper.writeValueAsString(sign(data));

    }
}
