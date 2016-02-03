module: sodium
synopsis: friendly interface to signing
author: Bruce Mitchener, Jr.
copyright: See LICENSE file in this distribution.

define class <ed25519-public-signing-key> (<public-signing-key>)
end class;

define class <ed25519-secret-signing-key> (<secret-signing-key>)
end class;

define function crypto-sign-ed25519-keypair
    ()
 => (public-key :: <ed25519-public-signing-key>,
     secret-key :: <ed25519-secret-signing-key>)
  let public-key-data = make(<C-string>, size: $crypto-sign-ed25519-PUBLICKEYBYTES);
  let secret-key-data = make(<C-string>, size: $crypto-sign-ed25519-SECRETKEYBYTES);
  let res = %crypto-sign-ed25519-keypair(public-key-data, secret-key-data);
  check-error(res, "crypto-sign-ed25519-keypair");
  let public-key = make(<ed25519-public-signing-key>, data: public-key-data);
  let secret-key = make(<ed25519-secret-signing-key>, data: secret-key-data);
  values(public-key, secret-key)
end function;

define inline function crypto-sign-ed25519-helper
    (payload :: <C-string>, payload-size :: <integer>,
     secret-key :: <ed25519-secret-signing-key>)
 => (signed-payload :: <signed-payload>)
  let signed-payload = make(<C-string>, size: payload.size + $crypto-sign-ed25519-BYTES);
  let signed-payload-len = make(<C-long*>);
  let res = %crypto-sign-ed25519(signed-payload, signed-payload-len,
                                 payload, payload-size,
                                 secret-signing-key-data(secret-key));
  check-error(res, "crypto-sign-ed25519");
  make(<signed-payload>, data: signed-payload,
       size: as(<integer>, C-long-at(signed-payload-len)),
       original-size: payload-size)
end function;

define method crypto-sign
    (payload :: <byte-vector>, secret-key :: <ed25519-secret-signing-key>)
 => (signed-payload :: <signed-payload>)
  with-c-string (payload-data = payload)
    crypto-sign-ed25519-helper(payload-data, payload.size, secret-key)
  end with-c-string
end method;

define method crypto-sign
    (payload :: <byte-string>, secret-key :: <ed25519-secret-signing-key>)
 => (signed-payload :: <signed-payload>)
  with-c-string (payload-data = payload)
    crypto-sign-ed25519-helper(payload-data, payload.size, secret-key)
  end with-c-string
end method;

define method crypto-sign-open
    (signed-payload :: <signed-payload>,
     public-key :: <ed25519-public-signing-key>)
 => (payload :: <byte-string>)
  let unsigned-message
    = make(<C-string>, size: signed-payload-size(signed-payload) - $crypto-sign-ed25519-BYTES);
  let unsigned-message-len = make(<C-long*>);
  let res = %crypto-sign-ed25519-open(unsigned-message, unsigned-message-len,
                                      signed-payload-data(signed-payload),
                                      signed-payload-size(signed-payload),
                                      public-signing-key-data(public-key));
  check-error(res, "crypto-sign-ed25519-open");
  as(<byte-string>, unsigned-message)
end method;

define method crypto-sign-detached
    (payload :: type-union(<byte-vector>, <byte-string>),
     secret-key :: <ed25519-secret-signing-key>)
 => (signature :: <detached-signature>)
  let signature-data = make(<C-string>, size: $crypto-sign-BYTES);
  let signature-data-size = make(<C-long*>);
  with-c-string (payload-data = payload)
    let res = %crypto-sign-ed25519-detached(signature-data, signature-data-size,
                                            payload-data, payload.size,
                                            secret-signing-key-data(secret-key));
    check-error(res, "crypto-sign-ed25519-detached");
  end with-c-string;
  make(<detached-signature>, data: signature-data,
       size: as(<integer>, C-long-at(signature-data-size)))
end method;

define method crypto-sign-verify-detached
    (signature :: <detached-signature>,
     payload :: type-union(<byte-vector>, <byte-string>),
     public-key :: <ed25519-public-signing-key>)
 => ()
  with-c-string (payload-data = payload)
    let res
      = %crypto-sign-ed25519-verify-detached(detached-signature-data(signature),
                                             payload-data, payload.size,
                                             public-signing-key-data(public-key));
    check-error(res, "crypto-sign-ed25519-verify-detached");
  end with-c-string;
end method;

define method crypto-sign-ed25519-sk-to-pk
    (secret-key :: <ed25519-secret-signing-key>)
 => (public-key :: <ed25519-public-signing-key>)
  let public-key-data = make(<C-string>, size: $crypto-sign-ed25519-PUBLICKEYBYTES);
  let res = %crypto-sign-ed25519-sk-to-pk(public-key-data, secret-signing-key-data(secret-key));
  check-error(res, "crypto-sign-ed25519-sk-to-pk");
  make(<ed25519-public-signing-key>, data: public-key-data);
end method;
