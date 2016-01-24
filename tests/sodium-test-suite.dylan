module: sodium-test-suite
synopsis: Test suite for the sodium library.

define test sign-generate-keys ()
  let public-key = make(<C-string>, size: $crypto-sign-PUBLICKEYBYTES);
  let secret-key = make(<C-string>, size: $crypto-sign-SECRETKEYBYTES);
  assert-equal(0, crypto-sign-keypair(public-key, secret-key));
end test sign-generate-keys;

define test sign-round-trip ()
  let public-key = make(<C-string>, size: $crypto-sign-PUBLICKEYBYTES);
  let secret-key = make(<C-string>, size: $crypto-sign-SECRETKEYBYTES);
  assert-equal(0, crypto-sign-keypair(public-key, secret-key));

  let message = "Hello there!";
  let signed-message = make(<C-string>, size: message.size + $crypto-sign-BYTES);
  let signed-message-len = make(<C-long*>);
  with-c-string (c-message = message)
    assert-equal(0, crypto-sign(signed-message, signed-message-len,
                                c-message, message.size,
                                secret-key));
  end with-c-string;

  let unsigned-message = make(<C-string>, size: message.size);
  let unsigned-message-len = make(<C-long*>);
  assert-equal(0, crypto-sign-open(unsigned-message, unsigned-message-len,
                                   signed-message, as(<integer>, C-long-at(signed-message-len)),
                                   public-key));
  assert-equal(message, as(<byte-string>, unsigned-message));
end test sign-round-trip;

define suite sodium-test-suite ()
  test sign-generate-keys;
  test sign-round-trip;
end suite;
