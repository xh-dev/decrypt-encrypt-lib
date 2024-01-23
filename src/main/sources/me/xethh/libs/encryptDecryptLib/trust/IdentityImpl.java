package me.xethh.libs.encryptDecryptLib.trust;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.xethh.libs.toolkits.commons.encryption.RsaEncryption;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.val;
import me.xethh.libs.encryptDecryptLib.op.deen.DeEnCryptor;
import me.xethh.libs.encryptDecryptLib.op.signing.Signer;
import me.xethh.libs.encryptDecryptLib.op.signing.Verifier;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class IdentityImpl implements Identity{
    @Getter
    private final PublicKey publicKey;
    @Getter
    private final PrivateKey privateKey;
    @Getter
    private final String name;
    @Getter
    private final String salt;
    @Getter
    private final String uid;
    @Getter
    private final String signature;
    private final ObjectMapper mapper;

    public IdentityImpl(PublicKey publicKey, PrivateKey privateKey, String uid, String name, String salt, String signature, ObjectMapper mapper) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.name = name;
        this.salt = salt;
        this.uid = uid;
        this.signature = signature;
        this.mapper = mapper;
    }
    public IdentityImpl(PublicKey publicKey, PrivateKey privateKey, String uid, String name, String salt, ObjectMapper mapper) {
        this(
                publicKey,
                privateKey,
                uid,
                name,
                salt,
                Signer.instance(privateKey).sign(
                        String.format("%s|%s", uid, Base64.getEncoder().encodeToString(publicKey.getEncoded()))
                ).getSignature(),
                mapper
        );
    }
    public IdentityImpl(PublicKey publicKey, PrivateKey privateKey, String name, String salt, ObjectMapper mapper) {
        this(
                publicKey,
                privateKey,
                genUid(name, salt),
                name,
                salt,
                mapper
        );
    }

    @SneakyThrows
    private static String genUid(String name, String salt){
        val digest = MessageDigest.getInstance("SHA-256");
        digest.update(name.getBytes(StandardCharsets.UTF_8));
        digest.update(salt.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(digest.digest());
    }

    @SneakyThrows
    private static String genSalt(){
        val rBytes = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(rBytes);
        return Base64.getEncoder().encodeToString(rBytes);
    }
    public IdentityImpl(PublicKey publicKey, PrivateKey privateKey, String name, ObjectMapper mapper) {
        this(publicKey, privateKey, name, genSalt(), mapper);
    }

    public IdentityImpl(KeyPair keyPair, String name, ObjectMapper mapper) {
        this(keyPair.getPublic(),keyPair.getPrivate(),name, mapper);
    }

    public IdentityImpl(String name, ObjectMapper mapper){
        this(RsaEncryption.keyPair(), name, mapper);
    }
    public IdentityImpl(String name){
        this(RsaEncryption.keyPair(),name, new ObjectMapper());
    }

    @Override
    public String uid() {
        return getUid();
    }

    @Override
    public String name() {
        return getName();
    }

    @Override
    public PublicKey publicKey() {
        return getPublicKey();
    }

    @Override
    public String fingerPrint() {
        return getSignature();
    }

    @Override
    public Signer signer() {
        return Signer.instance(privateKey, mapper);
    }

    @Override
    public Verifier verifier() {
        return Verifier.instance(publicKey);
    }

    @Override
    public DeEnCryptor deenCryptor() {
        return DeEnCryptor.instance(publicKey, privateKey, mapper);
    }

    @Override
    @SneakyThrows
    public NameCard mySelf(List<Identity> identityList) {
        return mySelf(identityList, true);
    }

    @Override
    public NameCard mySelf(List<Identity> trustedIdentity, Boolean withSelf) {
        val trusted = trustedIdentity.stream().filter(this::isTrusted).map(Identity::uid);
        return NameCard.instance(
                name,
                uid,
                publicKey,
                signer()
                        .signMultiple(
                                name, uid,
                                Base64.getEncoder().encodeToString(publicKey.getEncoded())
                        ).getSignature(),
                uid(),
                withSelf?
                        Stream.concat(Stream.of(uid()), trusted).collect(Collectors.toList())
                        :trusted.collect(Collectors.toList())
        );
    }

    @Override
    public boolean isTrusted(Identity identity) {
        return true;
    }
}
