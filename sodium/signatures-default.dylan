module: sodium
synopsis: friendly interface to signing
author: Bruce Mitchener, Jr.
copyright: See LICENSE file in this distribution.

define class <default-public-signing-key> (<public-signing-key>)
end class;

define class <default-secret-signing-key> (<secret-signing-key>)
end class;

define function crypto-sign-keypair
    ()
 => (public-key :: <default-public-signing-key>,
     secret-key :: <default-secret-signing-key>)
  let public-key-data = make(<byte-vector>, size: $crypto-sign-PUBLICKEYBYTES);
  let secret-key-data = make(<byte-vector>, size: $crypto-sign-SECRETKEYBYTES);
  let res = %crypto-sign-keypair(byte-storage-address(public-key-data),
                                 byte-storage-address(secret-key-data));
  check-error(res, "crypto-sign-keypair");
  let public-key = make(<default-public-signing-key>, data: public-key-data);
  let secret-key = make(<default-secret-signing-key>, data: secret-key-data);
  values(public-key, secret-key)
end function;

define method crypto-sign
    (payload :: type-union(<byte-vector>, <byte-string>),
     secret-key :: <default-secret-signing-key>)
 => (signed-payload :: <signed-payload>)
  let signed-payload = make(<byte-vector>, size: payload.size + $crypto-sign-BYTES);
  let signed-payload-len = make(<C-long*>);
  let res = %crypto-sign(byte-storage-address(signed-payload), signed-payload-len,
                         byte-storage-address(payload), payload.size,
                         byte-storage-address(secret-signing-key-data(secret-key)));
  check-error(res, "crypto-sign");
  make(<signed-payload>, data: signed-payload,
       size: as(<integer>, C-long-at(signed-payload-len)))
end method;

define method crypto-sign-open
    (signed-payload :: <signed-payload>,
     public-key :: <default-public-signing-key>)
 => (payload :: <byte-vector>)
  let unsigned-message
    = make(<byte-vector>, size: signed-payload-size(signed-payload) - $crypto-sign-BYTES);
  let unsigned-message-len = make(<C-long*>);
  let payload = signed-payload-data(signed-payload);
  let payload-size = signed-payload-size(signed-payload);
  let res = %crypto-sign-open(byte-storage-address(unsigned-message), unsigned-message-len,
                              byte-storage-address(payload),
                              payload-size,
                              byte-storage-address(public-signing-key-data(public-key)));
  check-error(res, "crypto-sign-open");
  unsigned-message
end method;

define method crypto-sign-detached
    (payload :: type-union(<byte-vector>, <byte-string>),
     secret-key :: <default-secret-signing-key>)
 => (signature :: <detached-signature>)
  let signature-data = make(<byte-vector>, size: $crypto-sign-BYTES);
  let signature-data-size = make(<C-long*>);
  let res = %crypto-sign-detached(byte-storage-address(signature-data), signature-data-size,
                                  byte-storage-address(payload), payload.size,
                                  byte-storage-address(secret-signing-key-data(secret-key)));
  check-error(res, "crypto-sign-detached");
  make(<detached-signature>, data: signature-data,
       size: as(<integer>, C-long-at(signature-data-size)))
end method;

define method crypto-sign-verify-detached
    (signature :: <detached-signature>,
     payload :: type-union(<byte-vector>, <byte-string>),
     public-key :: <default-public-signing-key>)
 => ()
  let res
    = %crypto-sign-verify-detached(byte-storage-address(detached-signature-data(signature)),
                                   byte-storage-address(payload), payload.size,
                                   byte-storage-address(public-signing-key-data(public-key)));
  check-error(res, "crypto-sign-verify-detached");
end method;
