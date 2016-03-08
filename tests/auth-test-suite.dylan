module: sodium-test-suite
synopsis: Test suite for the signatures functionality in the sodium library.

define test crypto-auth-test ()
  // This is taken from Test Case AUTH512-3 in https://tools.ietf.org/html/rfc4868
  let key = make(<byte-vector>, size: $CRYPTO-AUTH-KEYBYTES, fill: as(<byte>, 'a'));
  let data = make(<byte-vector>, size: 50, fill: as(<byte>, 'd'));

  let hash = crypto-auth(data, key);
  assert-no-errors(crypto-auth-verify(hash, data, key));

  let bad-hash = copy-sequence(hash);
  bad-hash[0] := bad-hash[0] + 1;
  assert-signals(<sodium-error>, crypto-auth-verify(bad-hash, data, key));
end test;

define test crypto-auth-byte-string-test ()
  // This is taken from Test Case AUTH512-3 in https://tools.ietf.org/html/rfc4868
  let key = make(<byte-vector>, size: $CRYPTO-AUTH-KEYBYTES, fill: as(<byte>, 'a'));
  let data = make(<byte-string>, size: 50, fill: 'd');

  let hash = crypto-auth(data, key);
  assert-no-errors(crypto-auth-verify(hash, data, key));
end test;

define suite auth-test-suite ()
  test crypto-auth-test;
  test crypto-auth-byte-string-test;
end suite;
