package me.xethh.libs.encryptDecryptLib.bdd;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.xethh.libs.toolkits.commons.encryption.RsaEncryption;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import lombok.SneakyThrows;
import lombok.val;
import me.xethh.libs.encryptDecryptLib.dataModel.SignedData;
import me.xethh.libs.encryptDecryptLib.op.deen.Signer;
import me.xethh.libs.encryptDecryptLib.op.deen.Verifier;

import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class GeneralSignAndVerifyTest {
    private PublicKey senderPublicKey;
    private PrivateKey senderPrivateKey;
    private static final String DATA = "hello world";
    SignedData signedData;

    @Given("Ava is the sender, having sender public key and sender private key")
    public void avaIsTheSenderHavingSenderPublicKeyAndSenderPrivateKey() {
        val kp = RsaEncryption.keyPair();
        this.senderPublicKey = kp.getPublic();
        this.senderPrivateKey = kp.getPrivate();
    }

    @And("Ava give Bernice her sender public key for verify the signature")
    public void avaGiveBerniceHerSenderPublicKeyForVerifyTheSignature() {
    }

    @When("Ava sign the message content \\(`hello world`) with sender private key")
    public void avaSignTheMessageContentHelloWorldWithSenderPrivateKey() {
        signedData = Signer.instance(senderPrivateKey).sign(DATA);
    }

    @Then("Bernice should able to verify the signature")
    public void berniceShouldAbleToVerifyTheSignature() {
        assertTrue(Verifier.instance(senderPublicKey).verify(signedData));
    }

    String signedDataStr;
    @When("Ava sign the message content \\(`hello world`) with sender private key in string format")
    public void avaSignTheMessageContentHelloWorldWithSenderPrivateKeyInStringFormat() {
        signedDataStr = Signer.instance(senderPrivateKey, new ObjectMapper()).signToJson(DATA);
    }

    @Then("Bernice convert the string into SigneddData object")
    @SneakyThrows
    public void berniceConvertTheStringIntoSigneddDataObject() {
        signedData = new ObjectMapper().readValue(signedDataStr, new TypeReference<SignedData>() {
        });
    }
}
