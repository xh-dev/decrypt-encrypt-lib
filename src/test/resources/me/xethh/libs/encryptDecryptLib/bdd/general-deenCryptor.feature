Feature: general encryption and decryption test
  Background:
    Given Ava created sender private key and sender public key
    And Bernice created receiver private key and receiver public key

  Scenario: Ava encrypt a `hello world` to Bernice
    When Ava encrypt the message(`hello world`) with receiver public key (Bernice's key)
    And Bernice decrypt the message from Ava
    Then Bernice should receive `helloworld` by decrypting the message

  Scenario: Ava encrypt a small java object to Bernice
    Given Ava encrypt a small java object with receiver public key (Bernice's key) as base 64 encoded string
    When Bernice decrypt the base 64 encoded screte as object
    Then Bernice should receive same content from the serialized object

  Scenario: Bernice try to decrypt random string
    When Bernice decrypt a random string with Ava's public key, `NotDataContainerException` is thrown

  Scenario: The message signature get modified by hacker
    When Ava encrypt the message(`hello world`) with receiver public key (Bernice's key)
    Then Bernice decrypt the modified message (signature changed) from Ava, Bernice should get `SignatureNotValidException`
