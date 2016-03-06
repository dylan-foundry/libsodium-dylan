module: sodium
synopsis: friendly interface to signing
author: Bruce Mitchener, Jr.
copyright: See LICENSE file in this distribution.

define function crypto-auth
    (payload :: type-union(<byte-vector>, <byte-string>),
     key :: <byte-vector>)
 => (hash :: <byte-vector>)
  assert(key.size == $crypto-auth-KEYBYTES);
  let hash = make(<byte-vector>, size: $crypto-auth-BYTES);
  let res = %crypto-auth(byte-storage-address(hash),
                         byte-storage-address(payload), payload.size,
                         byte-storage-address(key));
  check-error(res, "crypto-auth");
  hash
end function;

define function crypto-auth-verify
    (hash :: <byte-vector>,
     payload :: type-union(<byte-vector>, <byte-string>),
     key :: <byte-vector>)
 => ()
  assert(key.size == $crypto-auth-KEYBYTES);
  let res
    = %crypto-auth-verify(byte-storage-address(hash),
                          byte-storage-address(payload), payload.size,
                          byte-storage-address(key));
  check-error(res, "crypto-auth-verify");
end function;
