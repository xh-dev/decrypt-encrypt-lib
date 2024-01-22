Feature: general sign and verify test
  Background:
    Given Ava is the sender, having sender public key and sender private key
    Given Ava give Bernice her sender public key for verify the signature

  Scenario: simple sign and verify
    When Ava sign the message content (`hello world`) with sender private key
    Then Bernice should able to verify the signature

  Scenario: simple sign and verify
    When Ava sign the message content (`hello world`) with sender private key in string format
    Then Bernice convert the string into SigneddData object
    Then Bernice should able to verify the signature
