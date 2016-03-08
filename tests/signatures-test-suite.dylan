module: sodium-test-suite
synopsis: Test suite for the signatures functionality in the sodium library.

define test sign-generate-keys ()
  assert-no-errors(crypto-sign-keypair());
end test;

define function sign-round-trip-helper
    (public-key, secret-key, message)
  let signed-payload = crypto-sign(message, secret-key);

  let unsigned-message = crypto-sign-open(signed-payload, public-key);
  assert-equal(as(<byte-vector>, message), unsigned-message);

  let data = signed-payload-data(signed-payload);
  let old = data[3];
  data[3] := as(<integer>, data[3]) + 1;
  assert-signals(<sodium-error>,
                 crypto-sign-open(signed-payload, public-key),
                 "mutated signed payload fails to open");
  data[3] := old;

  let data = public-signing-key-data(public-key);
  let old = data[3];
  data[3] := as(<integer>, data[3]) + 1;
  assert-signals(<sodium-error>,
                 crypto-sign-open(signed-payload, public-key),
                 "mutated public key fails to open");
  data[3] := old;
end function;

define test sign-round-trip-byte-string-default ()
  let (public-key, secret-key) = crypto-sign-keypair();
  let message = "Hello there!";

  sign-round-trip-helper(public-key, secret-key, message);
end test;

define test sign-round-trip-byte-string-ed25519 ()
  let (public-key, secret-key) = crypto-sign-ed25519-keypair();
  let message = "Hello there!";

  sign-round-trip-helper(public-key, secret-key, message);
end test;

define test sign-round-trip-byte-vector-default ()
  let (public-key, secret-key) = crypto-sign-keypair();
  let message = as(<byte-vector>, "Hello there!");

  sign-round-trip-helper(public-key, secret-key, message);
end test;

define test sign-round-trip-byte-vector-ed25519 ()
  let (public-key, secret-key) = crypto-sign-ed25519-keypair();
  let message = as(<byte-vector>, "Hello there!");

  sign-round-trip-helper(public-key, secret-key, message);
end test;

define function sign-round-trip-detached-helper
    (public-key, secret-key)
 => ()
  let message = "Detachment and objectivity.";
  let signature = crypto-sign-detached(message, secret-key);
  assert-no-errors(crypto-sign-verify-detached(signature, message, public-key));

  let data = detached-signature-data(signature);
  let old = data[3];
  data[3] := as(<integer>, data[3]) + 1;
  assert-signals(<sodium-error>,
                 crypto-sign-verify-detached(signature, message, public-key),
                 "mutated signature fails to open");
  data[3] := old;
end function;

define test sign-round-trip-detached-default ()
  let (public-key, secret-key) = crypto-sign-keypair();

  sign-round-trip-detached-helper(public-key, secret-key);
end test;

define test sign-round-trip-detached-ed25519 ()
  let (public-key, secret-key) = crypto-sign-ed25519-keypair();

  sign-round-trip-detached-helper(public-key, secret-key);
end test;

define test sign-ed25519-sk-to-pk ()
  let (public-key, secret-key) = crypto-sign-ed25519-keypair();
  let extracted-public-key = crypto-sign-ed25519-sk-to-pk(secret-key);
  assert-equal(public-signing-key-data(public-key),
               public-signing-key-data(extracted-public-key));
end test;

define suite signatures-test-suite ()
  test sign-generate-keys;
  test sign-round-trip-byte-string-default;
  test sign-round-trip-byte-string-ed25519;
  test sign-round-trip-byte-vector-default;
  test sign-round-trip-byte-vector-ed25519;
  test sign-round-trip-detached-default;
  test sign-round-trip-detached-ed25519;
  test sign-ed25519-sk-to-pk;
end suite;
