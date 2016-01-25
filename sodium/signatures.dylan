module: sodium
synopsis: friendly interface to signing
author: Bruce Mitchener, Jr.
copyright: See LICENSE file in this distribution.

define class <public-signing-key> (<object>)
  constant slot public-signing-key-data :: <C-string>,
    required-init-keyword: data:;
end class;

define class <secret-signing-key> (<object>)
  constant slot secret-signing-key-data :: <C-string>,
    required-init-keyword: data:;
end class;

define class <signed-payload> (<object>)
  constant slot signed-payload-data :: <C-string>,
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
 => (payload :: <byte-string>);
