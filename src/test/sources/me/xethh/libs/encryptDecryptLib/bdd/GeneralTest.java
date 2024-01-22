package me.xethh.libs.encryptDecryptLib.bdd;

import dev.xethh.libs.toolkits.commons.encryption.RsaEncryption;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.*;
import me.xethh.libs.encryptDecryptLib.DataContainer;
import me.xethh.libs.encryptDecryptLib.DeEnCryptor;
import me.xethh.libs.encryptDecryptLib.JsonUtils;
import me.xethh.libs.encryptDecryptLib.exceptions.NotDataContainerException;
import me.xethh.libs.encryptDecryptLib.exceptions.SignatureNotValidException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class GeneralTest {
    private static final String MSG_CONTENT="hello world";
    private PrivateKey senderPriKey;
    private PublicKey senderPubKey;
    private PrivateKey receiverPriKey;
    private PublicKey receiverPubKey;

    private String msg;
    private Optional<String> decryptedMsg;
    private Optional<O> decryptedObject;

    @Given("Ava created sender private key and sender public key")
    public void ava_created_sender_private_key_and_sender_public_key() {
        val pair = RsaEncryption.keyPair();
        this.senderPriKey = pair.getPrivate();
        this.senderPubKey = pair.getPublic();
    }

    @Given("Bernice created receiver private key and receiver public key")
    public void bernice_created_receiver_private_key_and_receiver_public_key() {
        val pair = RsaEncryption.keyPair();
        this.receiverPriKey = pair.getPrivate();
        this.receiverPubKey = pair.getPublic();
    }

    @When("Ava encrypt the message\\(`hello world`) with receiver public key \\(Bernice's key)")
    public void ava_encrypt_the_message_hello_world_with_receiver_public_key_bernice_s_key() {
        val encrypt =DeEnCryptor.of(senderPubKey, senderPriKey);
        msg = encrypt.encryptToJsonContainer(receiverPubKey, MSG_CONTENT);
    }

    @When("Bernice decrypt the message from Ava")
    public void bernice_decrypt_the_message_from_ava() {
        decryptedMsg = DeEnCryptor.of(receiverPubKey, receiverPriKey).decryptJsonContainer(senderPubKey, this.msg);
    }

    @Then("Bernice should receive `helloworld` by decrypting the message")
    public void bernice_should_receive_helloworld_by_decrypting_the_message() {
        assertTrue(decryptedMsg.isPresent());
        assertEquals(MSG_CONTENT,decryptedMsg.get());
    }

    @Then("Bernice decrypt a random string with Ava's public key, `NotDataContainerException` is thrown")
    public void berniceDecryptARandomStringWithAvaSPublicKeyNotDataContainerExceptionIsThrown() {
        assertThrows(NotDataContainerException.class, ()->{
            DeEnCryptor.of(receiverPubKey, receiverPriKey).decryptJsonContainer(senderPubKey, "werwjaklsdfjaskldfjaslkd");
        });
    }

    @Then("Bernice decrypt the modified message \\(signature changed) from Ava, Bernice should get `SignatureNotValidException`")
    public void berniceDecryptTheModifiedMessageSignatureChangedFromAvaBerniceShouldGetSignatureNotValidException() {
        assertThrows(SignatureNotValidException.class, ()->{
            val mapper = DeEnCryptor.of(senderPubKey, senderPriKey).getMapper();
            val container = mapper.readValue(this.msg, DataContainer.class);
            container.setSign("kfPlZTOU8efDOgdP422knzmZxD43lAeL8zEkDhGkCTTHeAYdC16FQyimg7OaKhHOumwYehOr/aaJpVt1WyUO38h6R90iar+sQhpr9TKmq1MGsGuivHt8kG+EN5dc/B5Ek/qKy1zvXfw7CSFBa5fpXXjbsYVjFf/Acs2AFIBWtGbVMznaIMCbHZftZ3j7gFB/JCCwldrwjW7J0nQt3NmsrLO55BAhy5zvV1dgQbtKH+Z7cTAIqDXXNE0Ld1dFGZKGvsZmERJkhRHM8oYmYs83kq9OQLRkfLkzBbomSHrq9UPsIGQBLh7x9LEL3ppHPHVxGMtdfWx26KQ6gg4Fw/sOeZOp2SlweaQgpyhQibS7vnFINON3SrorOZ6K6eDjmuMajfJ1B9XRNhsxToCWTysszpFL6lfabxeWcMoQN45HIljOdxCiPQFsXa1bV3f00o0IJyInLdKJnlU7gJM3Gm7rX71BilmBpX7Kf7FKFCkOWC2shx/za0yc5XJ7hkFUpXSj+sDI95KWDhZOB0wWdDGW2INVG9BQH2SwEq5X1bynoFbn70ot7SaI3vExP6WGyLZ+1J0dNUfrDrs3bVZmgQcwDnUDe7m/9WYIghX4ftb3nENFvrrWl7xEB3CnTIunKLDOByZc81JYoIC0jo7y+3Flm6WFYO2UUDDOtYw3z43FDUc=");
            val newMessage = mapper.writeValueAsString(container);
            DeEnCryptor.of(receiverPubKey, receiverPriKey).decryptJsonContainer(senderPubKey, newMessage);

        });
    }

    @When("Bernice decrypt the base 64 encoded screte as object")
    public void berniceDecryptTheBaseEncodedScreteAsObject() {
        assertDoesNotThrow(()->{
            val decryptor = DeEnCryptor.of(receiverPubKey, receiverPriKey);
            decryptedObject = decryptor.decryptJsonContainer(senderPubKey, msg)
                    .map(it->
                        JsonUtils.asClass(it, decryptor.getMapper(), O.class)
                    )
                    ;
        });
    }


    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    public static class O {
        private int value;
    }
    @Given("Ava encrypt a small java object with receiver public key \\(Bernice's key) as base 64 encoded string")
    public void avaEncryptASmallJavaObjectWithReceiverPublicKeyBerniceSKeyAsBaseEncodedString() {
        val encrypt =DeEnCryptor.of(senderPubKey, senderPriKey);
        msg = encrypt.encryptObjectToJsonContainer(receiverPubKey, O.builder().value(20).build());
    }

    @Then("Bernice should receive same content from the serialized object")
    public void berniceShouldReceiveSameContentFromTheSerializedObject() {
        assertNotNull(decryptedObject);
        assertTrue(decryptedObject.isPresent());
        assertEquals(20, decryptedObject.get().getValue());
    }

}
