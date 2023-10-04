package me.xeth.libs.encryptDecryptLib;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.xethh.libs.toolkits.commons.encryption.AesEncryption;
import dev.xethh.libs.toolkits.commons.encryption.RsaEncryption;
import me.xethh.utils.functionalPacks.Scope;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;

public class Ava {
    private static final ObjectMapper mapper;

    static {
        mapper = new ObjectMapper();
    }

    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public static ObjectMapper getMapper() {
        return mapper;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public Ava(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public static Ava of(PublicKey publicKey, PrivateKey privateKey) {
        return new Ava(publicKey, privateKey);
    }

    public <O> Envelope encrypt(Bernice receiver, O in) throws JsonProcessingException {
        String data = mapper.writeValueAsString(in);
        IvParameterSpec iv = AesEncryption.iv();
        SecretKey key = AesEncryption.secretKey();
        String encrypted = AesEncryption.encrypt(data, key, iv);
        //val sign = AesEncryption.sign(key, iv, data)
        String sign = RsaEncryption.sign(data, privateKey);

        DataContainer con = Scope.of(new DataContainer())
                .apply(it -> {
                    it.setData(encrypted);
                    it.setSign(sign);
                    it.setIv(
                            Scope.of(iv)
                                    .let(x -> Base64.getEncoder().encodeToString(x.getIV()))
                                    .let(x -> RsaEncryption.encrypt(x, receiver.getPublicKey()))
                                    .unscoped()
                    );
                    it.setKey(
                            Scope.of(key)
                                    .let(x -> Base64.getEncoder().encodeToString(x.getEncoded()))
                                    .let(x -> RsaEncryption.encrypt(x, receiver.getPublicKey()))
                                    .unscoped()
                    );
                })
                .unscoped();

        return new Envelope(Base64.getEncoder().encodeToString(mapper.writeValueAsBytes(con)));
    }


    public <I> Optional<I> decryptTypeReference(Bernice receiver, Envelope envelope, TypeReference<I> type) throws IOException {
        DataContainer dataContainer = mapper.readValue(Base64.getDecoder().decode(envelope.getData()), DataContainer.class);
        IvParameterSpec iv = AesEncryption.iv(Base64.getDecoder().decode(RsaEncryption.decrypt(dataContainer.getIv(), this.privateKey)));
        SecretKey key = AesEncryption.secretKey(Base64.getDecoder().decode(RsaEncryption.decrypt(dataContainer.getKey(), this.privateKey)));
        String dataStr = AesEncryption.decrypt(dataContainer.getData(), key, iv);
        boolean rs = RsaEncryption.verify(dataStr, dataContainer.getSign(), receiver.getPublicKey());
        if(rs){
            if(String.class.equals(type)){
                return Optional.of((I)dataStr);
            }
            else{
                I data = mapper.readValue(dataStr, type);
                return Optional.of(data);
            }
        }
        else{
            return Optional.empty();
        }
    }
    public <I> Optional<I> decryptJavaType(Bernice receiver, Envelope envelope, JavaType type) throws IOException {
        DataContainer dataContainer = mapper.readValue(Base64.getDecoder().decode(envelope.getData()), DataContainer.class);
        IvParameterSpec iv = AesEncryption.iv(Base64.getDecoder().decode(RsaEncryption.decrypt(dataContainer.getIv(), this.privateKey)));
        SecretKey key = AesEncryption.secretKey(Base64.getDecoder().decode(RsaEncryption.decrypt(dataContainer.getKey(), this.privateKey)));
        String dataStr = AesEncryption.decrypt(dataContainer.getData(), key, iv);
        boolean rs = RsaEncryption.verify(dataStr, dataContainer.getSign(), receiver.getPublicKey());
        if(rs){
            if(String.class.equals(type)){
                return Optional.of((I)dataStr);
            }
            else{
                I data = mapper.readValue(dataStr, type);
                return Optional.of(data);
            }
        }
        else{
            return Optional.empty();
        }
    }
    public <I> Optional<I> decryptClass(Bernice receiver, Envelope envelope, Class<I> type) throws IOException {
        DataContainer dataContainer = mapper.readValue(Base64.getDecoder().decode(envelope.getData()), DataContainer.class);
        IvParameterSpec iv = AesEncryption.iv(Base64.getDecoder().decode(RsaEncryption.decrypt(dataContainer.getIv(), this.privateKey)));
        SecretKey key = AesEncryption.secretKey(Base64.getDecoder().decode(RsaEncryption.decrypt(dataContainer.getKey(), this.privateKey)));
        String dataStr = AesEncryption.decrypt(dataContainer.getData(), key, iv);
        boolean rs = RsaEncryption.verify(dataStr, dataContainer.getSign(), receiver.getPublicKey());
        if(rs){
            if(String.class.equals(type)){
                return Optional.of((I)dataStr);
            }
            else{
                I data = mapper.readValue(dataStr, type);
                return Optional.of(data);
            }
        }
        else{
            return Optional.empty();
        }


    }
}
