module: sodium
synopsis: bindings for secret key authentication
author: Bruce Mitchener, Jr.
copyright: See LICENSE file in this distribution.

define function crypto-auth-hmacsha512256
    (payload :: type-union(<byte-vector>, <byte-string>),
     key :: <byte-vector>)
 => (hash :: <byte-vector>)
  assert(key.size == $crypto-auth-hmacsha512256-KEYBYTES);
  let hash = make(<byte-vector>, size: $crypto-auth-hmacsha512256-BYTES);
  let res = %crypto-auth-hmacsha512256(byte-storage-address(hash),
                                       byte-storage-address(payload), payload.size,
                                       byte-storage-address(key));
  check-error(res, "crypto-auth-hmacsha512256");
  hash
end function;

define function crypto-auth-hmacsha512256-verify
    (hash :: <byte-vector>,
     payload :: type-union(<byte-vector>, <byte-string>),
     key :: <byte-vector>)
 => ()
  assert(key.size == $crypto-auth-hmacsha512256-KEYBYTES);
  let res
    = %crypto-auth-hmacsha512256-verify(byte-storage-address(hash),
                                        byte-storage-address(payload), payload.size,
                                        byte-storage-address(key));
  check-error(res, "crypto-auth-hmacsha512256-verify");
end function;
