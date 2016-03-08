module: sodium
synopsis: friendly interface to signing
author: Bruce Mitchener, Jr.
copyright: See LICENSE file in this distribution.

define class <public-signing-key> (<object>)
  constant slot public-signing-key-data :: <byte-vector>,
    required-init-keyword: data:;
end class;

define class <secret-signing-key> (<object>)
  constant slot secret-signing-key-data :: <byte-vector>,
    required-init-keyword: data:;
end class;

define class <signed-payload> (<object>)
  constant slot signed-payload-data :: <byte-vector>,
    required-init-keyword: data:;
  constant slot signed-payload-size :: <integer>,
    required-init-keyword: size:;
end class;

define sealed generic crypto-sign
    (payload :: type-union(<byte-vector>, <byte-string>),
     secret-key :: <secret-signing-key>)
 => (signed-payload :: <signed-payload>);

define sealed generic crypto-sign-open
    (signed-payload :: <signed-payload>,
     public-key :: <public-signing-key>)
 => (payload :: <byte-vector>);

define class <detached-signature> (<object>)
  constant slot detached-signature-data :: <byte-vector>,
    required-init-keyword: data:;
  constant slot detached-signature-size :: <integer>,
    required-init-keyword: size:;
end class;

define sealed generic crypto-sign-detached
    (payload :: type-union(<byte-vector>, <byte-string>),
     secret-key :: <secret-signing-key>)
 => (signature :: <detached-signature>);

define sealed generic crypto-sign-verify-detached
    (signature :: <detached-signature>,
     payload :: type-union(<byte-vector>, <byte-string>),
     public-key :: <public-signing-key>)
 => ();
