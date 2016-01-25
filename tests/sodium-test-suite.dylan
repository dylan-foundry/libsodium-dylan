module: sodium-test-suite
synopsis: Test suite for the sodium library.

define test sign-generate-keys ()
  assert-no-errors(crypto-sign-keypair());
end test sign-generate-keys;

define test sign-round-trip-byte-string-default ()
  let (public-key, secret-key) = crypto-sign-keypair();

  let message = "Hello there!";
  let signed-payload = crypto-sign(message, secret-key);

  let unsigned-message = crypto-sign-open(signed-payload, public-key);
  assert-equal(message, unsigned-message);
end test sign-round-trip-byte-string-default;

define test sign-round-trip-byte-string-ed25519 ()
  let (public-key, secret-key) = crypto-sign-ed25519-keypair();

  let message = "Hello there!";
  let signed-payload = crypto-sign(message, secret-key);

  let unsigned-message = crypto-sign-open(signed-payload, public-key);
  assert-equal(message, unsigned-message);
end test sign-round-trip-byte-string-ed25519;

define suite sodium-test-suite ()
  test sign-generate-keys;
  test sign-round-trip-byte-string-default;
  test sign-round-trip-byte-string-ed25519;
end suite;
