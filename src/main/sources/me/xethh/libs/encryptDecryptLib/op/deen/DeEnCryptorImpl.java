package me.xethh.libs.encryptDecryptLib.op.deen;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.val;
import me.xethh.libs.encryptDecryptLib.DeEnUtils;
import me.xethh.libs.encryptDecryptLib.dataModel.DataContainer;
import me.xethh.libs.encryptDecryptLib.encryption.AesEncryption;
import me.xethh.libs.encryptDecryptLib.encryption.RsaEncryption;
import me.xethh.libs.encryptDecryptLib.exceptions.NotDataContainerException;
import me.xethh.libs.encryptDecryptLib.exceptions.SerializationException;
import me.xethh.libs.encryptDecryptLib.exceptions.SignatureNotValidException;
import me.xethh.libs.encryptDecryptLib.op.deen.DeEnCryptor;
import me.xethh.utils.functionalPacks.Scope;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;

public class DeEnCryptorImpl implements DeEnCryptor {
    private final ObjectMapper mapper;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public ObjectMapper getMapper() {
        return mapper;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    protected DeEnCryptorImpl(PublicKey publicKey, PrivateKey privateKey, ObjectMapper om) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.mapper = om;
    }


    @Override
    public <O> DataContainer encryptObjectToContainer(PublicKey receiver, O in){
        try{
            String data = mapper.writeValueAsString(in);
            return encryptToContainer(receiver, data);
        } catch (JsonProcessingException exception){
            throw new SerializationException(exception);
        }
    }

    @Override
    public <O> String encryptObjectToJsonContainer(PublicKey receiver, O data) {
        try{
            return encryptToJsonContainer(receiver, mapper.writeValueAsString(data));
        } catch (JsonProcessingException ex){
            throw new SerializationException(ex);
        }
    }

    @Override
    public String encryptToJsonContainer(PublicKey receiver, String data) {
        return DeEnUtils.dataContainerAsString(mapper, encryptToContainer(receiver, data));
    }

    @Override
    public DataContainer encryptToContainer(PublicKey receiver, String data){
        IvParameterSpec iv = AesEncryption.iv();
        SecretKey key = AesEncryption.secretKey();
        String encrypted = AesEncryption.encrypt(data, key, iv);
        //val sign = AesEncr
        // yption.sign(key, iv, data)
        String sign = RsaEncryption.sign(data, getPrivateKey());

        DataContainer con = Scope.of(new DataContainer())
                .apply(it -> {
                    it.setData(encrypted);
                    it.setSign(sign);
                    it.setIv(
                            Scope.of(iv)
                                    .let(x -> Base64.getEncoder().encodeToString(x.getIV()))
                                    .let(x -> RsaEncryption.encrypt(x, receiver))
                                    .unscoped()
                    );
                    it.setKey(
                            Scope.of(key)
                                    .let(x -> Base64.getEncoder().encodeToString(x.getEncoded()))
                                    .let(x -> RsaEncryption.encrypt(x, receiver))
                                    .unscoped()
                    );
                })
                .unscoped();
        return con;
    }

    @Override
    public Optional<String> decryptContainer(PublicKey receiver, DataContainer dataContainer){
        IvParameterSpec iv = AesEncryption.iv(Base64.getDecoder().decode(RsaEncryption.decrypt(dataContainer.getIv(), getPrivateKey())));
        SecretKey key = AesEncryption.secretKey(Base64.getDecoder().decode(RsaEncryption.decrypt(dataContainer.getKey(), getPrivateKey())));
        String dataStr = AesEncryption.decrypt(dataContainer.getData(), key, iv);
        try{
            val rs = RsaEncryption.verify(dataStr, dataContainer.getSign(), receiver);
            if(rs){
                return Optional.of(dataStr);
            } else {
                throw new SignatureNotValidException();
            }
        } catch (SignatureNotValidException ex){
            throw ex;
        }
        catch (RuntimeException ex){
            if(ex.getMessage().equals("SignatureException")){
                throw new SignatureNotValidException();
            } else {
                throw ex;
            }
        }
    }
    @Override
    public Optional<String> decryptJsonContainer(PublicKey receiver, String data) {
        DataContainer dataContainer = null;
        try {
            dataContainer = mapper.readValue(data, DataContainer.class);
            return decryptContainer(receiver, dataContainer);
        } catch (JsonParseException ex){
            throw new NotDataContainerException(ex);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
