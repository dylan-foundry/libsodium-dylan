module: sodium
synopsis: friendly interface to hashing
author: Bruce Mitchener, Jr.
copyright: See LICENSE file in this distribution.

define function crypto-auth-hmacsha512
    (payload :: type-union(<byte-vector>, <byte-string>),
     key :: <byte-vector>)
 => (hash :: <byte-vector>)
  assert(key.size == $crypto-auth-hmacsha512-KEYBYTES);
  let hash = make(<byte-vector>, size: $crypto-auth-hmacsha512-BYTES);
  let res = %crypto-auth-hmacsha512(byte-storage-address(hash),
                                    byte-storage-address(payload), payload.size,
                                    byte-storage-address(key));
  check-error(res, "crypto-auth-hmacsha512");
  hash
end function;

define function crypto-auth-hmacsha512-verify
    (hash :: <byte-vector>,
     payload :: type-union(<byte-vector>, <byte-string>),
     key :: <byte-vector>)
 => ()
  assert(key.size == $crypto-auth-hmacsha512-KEYBYTES);
  let res
    = %crypto-auth-hmacsha512-verify(byte-storage-address(hash),
                                     byte-storage-address(payload), payload.size,
                                     byte-storage-address(key));
  check-error(res, "crypto-auth-hmacsha512-verify");
end function;
