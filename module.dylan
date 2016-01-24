module: dylan-user

define module sodium
  use common-dylan;
  use c-ffi;
  export
    $SODIUM-LIBRARY-VERSION-MAJOR,
    $SODIUM-LIBRARY-VERSION-MINOR,
    $SODIUM-VERSION-STRING,
    $crypto-aead-aes256gcm-ABYTES,
    $crypto-aead-aes256gcm-KEYBYTES,
    $crypto-aead-aes256gcm-NPUBBYTES,
    $crypto-aead-aes256gcm-NSECBYTES,
    $crypto-aead-chacha20poly1305-ABYTES,
    $crypto-aead-chacha20poly1305-IETF-NPUBBYTES,
    $crypto-aead-chacha20poly1305-KEYBYTES,
    $crypto-aead-chacha20poly1305-NPUBBYTES,
    $crypto-aead-chacha20poly1305-NSECBYTES,
    $crypto-auth-BYTES,
    $crypto-auth-KEYBYTES,
    $crypto-auth-PRIMITIVE,
    $crypto-auth-hmacsha256-BYTES,
    $crypto-auth-hmacsha256-KEYBYTES,
    $crypto-auth-hmacsha512-BYTES,
    $crypto-auth-hmacsha512-KEYBYTES,
    $crypto-auth-hmacsha512256-BYTES,
    $crypto-auth-hmacsha512256-KEYBYTES,
    $crypto-box-BEFORENMBYTES,
    $crypto-box-BOXZEROBYTES,
    $crypto-box-MACBYTES,
    $crypto-box-NONCEBYTES,
    $crypto-box-PRIMITIVE,
    $crypto-box-PUBLICKEYBYTES,
    $crypto-box-SEALBYTES,
    $crypto-box-SECRETKEYBYTES,
    $crypto-box-SEEDBYTES,
    $crypto-box-ZEROBYTES,
    $crypto-box-curve25519xsalsa20poly1305-BEFORENMBYTES,
    $crypto-box-curve25519xsalsa20poly1305-BOXZEROBYTES,
    $crypto-box-curve25519xsalsa20poly1305-MACBYTES,
    $crypto-box-curve25519xsalsa20poly1305-NONCEBYTES,
    $crypto-box-curve25519xsalsa20poly1305-PUBLICKEYBYTES,
    $crypto-box-curve25519xsalsa20poly1305-SECRETKEYBYTES,
    $crypto-box-curve25519xsalsa20poly1305-SEEDBYTES,
    $crypto-box-curve25519xsalsa20poly1305-ZEROBYTES,
    $crypto-core-hsalsa20-CONSTBYTES,
    $crypto-core-hsalsa20-INPUTBYTES,
    $crypto-core-hsalsa20-KEYBYTES,
    $crypto-core-hsalsa20-OUTPUTBYTES,
    $crypto-core-salsa20-CONSTBYTES,
    $crypto-core-salsa20-INPUTBYTES,
    $crypto-core-salsa20-KEYBYTES,
    $crypto-core-salsa20-OUTPUTBYTES,
    $crypto-core-salsa2012-CONSTBYTES,
    $crypto-core-salsa2012-INPUTBYTES,
    $crypto-core-salsa2012-KEYBYTES,
    $crypto-core-salsa2012-OUTPUTBYTES,
    $crypto-core-salsa208-CONSTBYTES,
    $crypto-core-salsa208-INPUTBYTES,
    $crypto-core-salsa208-KEYBYTES,
    $crypto-core-salsa208-OUTPUTBYTES,
    $crypto-generichash-BYTES,
    $crypto-generichash-BYTES-MAX,
    $crypto-generichash-BYTES-MIN,
    $crypto-generichash-KEYBYTES,
    $crypto-generichash-KEYBYTES-MAX,
    $crypto-generichash-KEYBYTES-MIN,
    $crypto-generichash-PRIMITIVE,
    $crypto-generichash-blake2b-BYTES,
    $crypto-generichash-blake2b-BYTES-MAX,
    $crypto-generichash-blake2b-BYTES-MIN,
    $crypto-generichash-blake2b-KEYBYTES,
    $crypto-generichash-blake2b-KEYBYTES-MAX,
    $crypto-generichash-blake2b-KEYBYTES-MIN,
    $crypto-generichash-blake2b-PERSONALBYTES,
    $crypto-generichash-blake2b-SALTBYTES,
    $crypto-hash-BYTES,
    $crypto-hash-PRIMITIVE,
    $crypto-hash-sha256-BYTES,
    $crypto-hash-sha512-BYTES,
    $crypto-onetimeauth-BYTES,
    $crypto-onetimeauth-KEYBYTES,
    $crypto-onetimeauth-PRIMITIVE,
    $crypto-onetimeauth-poly1305-BYTES,
    $crypto-onetimeauth-poly1305-KEYBYTES,
    $crypto-pwhash-scryptsalsa208sha256-MEMLIMIT-INTERACTIVE,
    $crypto-pwhash-scryptsalsa208sha256-MEMLIMIT-SENSITIVE,
    $crypto-pwhash-scryptsalsa208sha256-OPSLIMIT-INTERACTIVE,
    $crypto-pwhash-scryptsalsa208sha256-OPSLIMIT-SENSITIVE,
    $crypto-pwhash-scryptsalsa208sha256-SALTBYTES,
    $crypto-pwhash-scryptsalsa208sha256-STRBYTES,
    $crypto-pwhash-scryptsalsa208sha256-STRPREFIX,
    $crypto-scalarmult-BYTES,
    $crypto-scalarmult-PRIMITIVE,
    $crypto-scalarmult-SCALARBYTES,
    $crypto-scalarmult-curve25519-BYTES,
    $crypto-scalarmult-curve25519-SCALARBYTES,
    $crypto-secretbox-BOXZEROBYTES,
    $crypto-secretbox-KEYBYTES,
    $crypto-secretbox-MACBYTES,
    $crypto-secretbox-NONCEBYTES,
    $crypto-secretbox-PRIMITIVE,
    $crypto-secretbox-ZEROBYTES,
    $crypto-secretbox-xsalsa20poly1305-BOXZEROBYTES,
    $crypto-secretbox-xsalsa20poly1305-KEYBYTES,
    $crypto-secretbox-xsalsa20poly1305-MACBYTES,
    $crypto-secretbox-xsalsa20poly1305-NONCEBYTES,
    $crypto-secretbox-xsalsa20poly1305-ZEROBYTES,
    $crypto-shorthash-BYTES,
    $crypto-shorthash-KEYBYTES,
    $crypto-shorthash-PRIMITIVE,
    $crypto-shorthash-siphash24-BYTES,
    $crypto-shorthash-siphash24-KEYBYTES,
    $crypto-sign-BYTES,
    $crypto-sign-PRIMITIVE,
    $crypto-sign-PUBLICKEYBYTES,
    $crypto-sign-SECRETKEYBYTES,
    $crypto-sign-SEEDBYTES,
    $crypto-sign-ed25519-BYTES,
    $crypto-sign-ed25519-PUBLICKEYBYTES,
    $crypto-sign-ed25519-SECRETKEYBYTES,
    $crypto-sign-ed25519-SEEDBYTES,
    $crypto-sign-edwards25519sha512batch-BYTES,
    $crypto-sign-edwards25519sha512batch-PUBLICKEYBYTES,
    $crypto-sign-edwards25519sha512batch-SECRETKEYBYTES,
    $crypto-stream-KEYBYTES,
    $crypto-stream-NONCEBYTES,
    $crypto-stream-PRIMITIVE,
    $crypto-stream-aes128ctr-BEFORENMBYTES,
    $crypto-stream-aes128ctr-KEYBYTES,
    $crypto-stream-aes128ctr-NONCEBYTES,
    $crypto-stream-chacha20-IETF-NONCEBYTES,
    $crypto-stream-chacha20-KEYBYTES,
    $crypto-stream-chacha20-NONCEBYTES,
    $crypto-stream-salsa20-KEYBYTES,
    $crypto-stream-salsa20-NONCEBYTES,
    $crypto-stream-salsa2012-KEYBYTES,
    $crypto-stream-salsa2012-NONCEBYTES,
    $crypto-stream-salsa208-KEYBYTES,
    $crypto-stream-salsa208-NONCEBYTES,
    $crypto-stream-xsalsa20-KEYBYTES,
    $crypto-stream-xsalsa20-NONCEBYTES,
    $crypto-verify-16-BYTES,
    $crypto-verify-32-BYTES,
    $crypto-verify-64-BYTES,
    <buf>,
    <char<@102>>,
    <close>,
    <crypto-aead-aes256gcm-state>,
    <crypto-auth-hmacsha256-state*>,
    <crypto-auth-hmacsha256-state>,
    <crypto-auth-hmacsha512-state*>,
    <crypto-auth-hmacsha512-state>,
    <crypto-auth-hmacsha512256-state>,
    <crypto-generichash-blake2b-state*>,
    <crypto-generichash-blake2b-state>,
    <crypto-generichash-state>,
    <crypto-hash-sha256-state*>,
    <crypto-hash-sha256-state>,
    <crypto-hash-sha512-state*>,
    <crypto-hash-sha512-state>,
    <crypto-onetimeauth-poly1305-state*>,
    <crypto-onetimeauth-poly1305-state>,
    <crypto-onetimeauth-state>,
    <implementation-name>,
    <random>,
    <randombytes-implementation*>,
    <randombytes-implementation>,
    <size-t*>,
    <statically-typed-pointer*>,
    <stir>,
    <uint32-t>,
    <uint64-t>,
    <uniform>,
    <unsigned-char*>,
    <unsigned-char<@512>*>,
    <unsigned-char<@512>>,
    <unsigned-long-long*>,
    crypto-aead-aes256gcm-abytes,
    crypto-aead-aes256gcm-beforenm,
    crypto-aead-aes256gcm-decrypt,
    crypto-aead-aes256gcm-decrypt-afternm,
    crypto-aead-aes256gcm-encrypt,
    crypto-aead-aes256gcm-encrypt-afternm,
    crypto-aead-aes256gcm-is-available,
    crypto-aead-aes256gcm-keybytes,
    crypto-aead-aes256gcm-npubbytes,
    crypto-aead-aes256gcm-nsecbytes,
    crypto-aead-aes256gcm-statebytes,
    crypto-aead-chacha20poly1305-abytes,
    crypto-aead-chacha20poly1305-decrypt,
    crypto-aead-chacha20poly1305-encrypt,
    crypto-aead-chacha20poly1305-ietf-decrypt,
    crypto-aead-chacha20poly1305-ietf-encrypt,
    crypto-aead-chacha20poly1305-ietf-npubbytes,
    crypto-aead-chacha20poly1305-keybytes,
    crypto-aead-chacha20poly1305-npubbytes,
    crypto-aead-chacha20poly1305-nsecbytes,
    crypto-auth,
    crypto-auth-bytes,
    crypto-auth-hmacsha256,
    crypto-auth-hmacsha256-bytes,
    crypto-auth-hmacsha256-final,
    crypto-auth-hmacsha256-init,
    crypto-auth-hmacsha256-keybytes,
    crypto-auth-hmacsha256-state$ictx,
    crypto-auth-hmacsha256-state$ictx-setter,
    crypto-auth-hmacsha256-state$octx,
    crypto-auth-hmacsha256-state$octx-setter,
    crypto-auth-hmacsha256-statebytes,
    crypto-auth-hmacsha256-update,
    crypto-auth-hmacsha256-verify,
    crypto-auth-hmacsha512,
    crypto-auth-hmacsha512-bytes,
    crypto-auth-hmacsha512-final,
    crypto-auth-hmacsha512-init,
    crypto-auth-hmacsha512-keybytes,
    crypto-auth-hmacsha512-state$ictx,
    crypto-auth-hmacsha512-state$ictx-setter,
    crypto-auth-hmacsha512-state$octx,
    crypto-auth-hmacsha512-state$octx-setter,
    crypto-auth-hmacsha512-statebytes,
    crypto-auth-hmacsha512-update,
    crypto-auth-hmacsha512-verify,
    crypto-auth-hmacsha512256,
    crypto-auth-hmacsha512256-bytes,
    crypto-auth-hmacsha512256-final,
    crypto-auth-hmacsha512256-init,
    crypto-auth-hmacsha512256-keybytes,
    crypto-auth-hmacsha512256-statebytes,
    crypto-auth-hmacsha512256-update,
    crypto-auth-hmacsha512256-verify,
    crypto-auth-keybytes,
    crypto-auth-primitive,
    crypto-auth-verify,
    crypto-box,
    crypto-box-afternm,
    crypto-box-beforenm,
    crypto-box-beforenmbytes,
    crypto-box-boxzerobytes,
    crypto-box-curve25519xsalsa20poly1305,
    crypto-box-curve25519xsalsa20poly1305-afternm,
    crypto-box-curve25519xsalsa20poly1305-beforenm,
    crypto-box-curve25519xsalsa20poly1305-beforenmbytes,
    crypto-box-curve25519xsalsa20poly1305-boxzerobytes,
    crypto-box-curve25519xsalsa20poly1305-keypair,
    crypto-box-curve25519xsalsa20poly1305-macbytes,
    crypto-box-curve25519xsalsa20poly1305-noncebytes,
    crypto-box-curve25519xsalsa20poly1305-open,
    crypto-box-curve25519xsalsa20poly1305-open-afternm,
    crypto-box-curve25519xsalsa20poly1305-publickeybytes,
    crypto-box-curve25519xsalsa20poly1305-secretkeybytes,
    crypto-box-curve25519xsalsa20poly1305-seed-keypair,
    crypto-box-curve25519xsalsa20poly1305-seedbytes,
    crypto-box-curve25519xsalsa20poly1305-zerobytes,
    crypto-box-detached,
    crypto-box-detached-afternm,
    crypto-box-easy,
    crypto-box-easy-afternm,
    crypto-box-keypair,
    crypto-box-macbytes,
    crypto-box-noncebytes,
    crypto-box-open,
    crypto-box-open-afternm,
    crypto-box-open-detached,
    crypto-box-open-detached-afternm,
    crypto-box-open-easy,
    crypto-box-open-easy-afternm,
    crypto-box-primitive,
    crypto-box-publickeybytes,
    crypto-box-seal,
    crypto-box-seal-open,
    crypto-box-sealbytes,
    crypto-box-secretkeybytes,
    crypto-box-seed-keypair,
    crypto-box-seedbytes,
    crypto-box-zerobytes,
    crypto-core-hsalsa20,
    crypto-core-hsalsa20-constbytes,
    crypto-core-hsalsa20-inputbytes,
    crypto-core-hsalsa20-keybytes,
    crypto-core-hsalsa20-outputbytes,
    crypto-core-salsa20,
    crypto-core-salsa20-constbytes,
    crypto-core-salsa20-inputbytes,
    crypto-core-salsa20-keybytes,
    crypto-core-salsa20-outputbytes,
    crypto-core-salsa2012,
    crypto-core-salsa2012-constbytes,
    crypto-core-salsa2012-inputbytes,
    crypto-core-salsa2012-keybytes,
    crypto-core-salsa2012-outputbytes,
    crypto-core-salsa208,
    crypto-core-salsa208-constbytes,
    crypto-core-salsa208-inputbytes,
    crypto-core-salsa208-keybytes,
    crypto-core-salsa208-outputbytes,
    crypto-generichash,
    crypto-generichash-blake2b,
    crypto-generichash-blake2b-bytes,
    crypto-generichash-blake2b-bytes-max,
    crypto-generichash-blake2b-bytes-min,
    crypto-generichash-blake2b-final,
    crypto-generichash-blake2b-init,
    crypto-generichash-blake2b-init-salt-personal,
    crypto-generichash-blake2b-keybytes,
    crypto-generichash-blake2b-keybytes-max,
    crypto-generichash-blake2b-keybytes-min,
    crypto-generichash-blake2b-personalbytes,
    crypto-generichash-blake2b-salt-personal,
    crypto-generichash-blake2b-saltbytes,
    crypto-generichash-blake2b-state$buf,
    crypto-generichash-blake2b-state$buf-setter,
    crypto-generichash-blake2b-state$buflen,
    crypto-generichash-blake2b-state$buflen-setter,
    crypto-generichash-blake2b-state$f,
    crypto-generichash-blake2b-state$f-setter,
    crypto-generichash-blake2b-state$h,
    crypto-generichash-blake2b-state$h-setter,
    crypto-generichash-blake2b-state$last-node,
    crypto-generichash-blake2b-state$last-node-setter,
    crypto-generichash-blake2b-state$t,
    crypto-generichash-blake2b-state$t-setter,
    crypto-generichash-blake2b-update,
    crypto-generichash-bytes,
    crypto-generichash-bytes-max,
    crypto-generichash-bytes-min,
    crypto-generichash-final,
    crypto-generichash-init,
    crypto-generichash-keybytes,
    crypto-generichash-keybytes-max,
    crypto-generichash-keybytes-min,
    crypto-generichash-primitive,
    crypto-generichash-statebytes,
    crypto-generichash-update,
    crypto-hash,
    crypto-hash-bytes,
    crypto-hash-primitive,
    crypto-hash-sha256,
    crypto-hash-sha256-bytes,
    crypto-hash-sha256-final,
    crypto-hash-sha256-init,
    crypto-hash-sha256-state$buf,
    crypto-hash-sha256-state$buf-setter,
    crypto-hash-sha256-state$count,
    crypto-hash-sha256-state$count-setter,
    crypto-hash-sha256-state$state,
    crypto-hash-sha256-state$state-setter,
    crypto-hash-sha256-statebytes,
    crypto-hash-sha256-update,
    crypto-hash-sha512,
    crypto-hash-sha512-bytes,
    crypto-hash-sha512-final,
    crypto-hash-sha512-init,
    crypto-hash-sha512-state$buf,
    crypto-hash-sha512-state$buf-setter,
    crypto-hash-sha512-state$count,
    crypto-hash-sha512-state$count-setter,
    crypto-hash-sha512-state$state,
    crypto-hash-sha512-state$state-setter,
    crypto-hash-sha512-statebytes,
    crypto-hash-sha512-update,
    crypto-onetimeauth,
    crypto-onetimeauth-bytes,
    crypto-onetimeauth-final,
    crypto-onetimeauth-init,
    crypto-onetimeauth-keybytes,
    crypto-onetimeauth-poly1305,
    crypto-onetimeauth-poly1305-bytes,
    crypto-onetimeauth-poly1305-final,
    crypto-onetimeauth-poly1305-init,
    crypto-onetimeauth-poly1305-keybytes,
    crypto-onetimeauth-poly1305-state$opaque,
    crypto-onetimeauth-poly1305-state$opaque-setter,
    crypto-onetimeauth-poly1305-update,
    crypto-onetimeauth-poly1305-verify,
    crypto-onetimeauth-primitive,
    crypto-onetimeauth-statebytes,
    crypto-onetimeauth-update,
    crypto-onetimeauth-verify,
    crypto-pwhash-scryptsalsa208sha256,
    crypto-pwhash-scryptsalsa208sha256-ll,
    crypto-pwhash-scryptsalsa208sha256-memlimit-interactive,
    crypto-pwhash-scryptsalsa208sha256-memlimit-sensitive,
    crypto-pwhash-scryptsalsa208sha256-opslimit-interactive,
    crypto-pwhash-scryptsalsa208sha256-opslimit-sensitive,
    crypto-pwhash-scryptsalsa208sha256-saltbytes,
    crypto-pwhash-scryptsalsa208sha256-str,
    crypto-pwhash-scryptsalsa208sha256-str-verify,
    crypto-pwhash-scryptsalsa208sha256-strbytes,
    crypto-pwhash-scryptsalsa208sha256-strprefix,
    crypto-scalarmult,
    crypto-scalarmult-base,
    crypto-scalarmult-bytes,
    crypto-scalarmult-curve25519,
    crypto-scalarmult-curve25519-base,
    crypto-scalarmult-curve25519-bytes,
    crypto-scalarmult-curve25519-scalarbytes,
    crypto-scalarmult-primitive,
    crypto-scalarmult-scalarbytes,
    crypto-secretbox,
    crypto-secretbox-boxzerobytes,
    crypto-secretbox-detached,
    crypto-secretbox-easy,
    crypto-secretbox-keybytes,
    crypto-secretbox-macbytes,
    crypto-secretbox-noncebytes,
    crypto-secretbox-open,
    crypto-secretbox-open-detached,
    crypto-secretbox-open-easy,
    crypto-secretbox-primitive,
    crypto-secretbox-xsalsa20poly1305,
    crypto-secretbox-xsalsa20poly1305-boxzerobytes,
    crypto-secretbox-xsalsa20poly1305-keybytes,
    crypto-secretbox-xsalsa20poly1305-macbytes,
    crypto-secretbox-xsalsa20poly1305-noncebytes,
    crypto-secretbox-xsalsa20poly1305-open,
    crypto-secretbox-xsalsa20poly1305-zerobytes,
    crypto-secretbox-zerobytes,
    crypto-shorthash,
    crypto-shorthash-bytes,
    crypto-shorthash-keybytes,
    crypto-shorthash-primitive,
    crypto-shorthash-siphash24,
    crypto-shorthash-siphash24-bytes,
    crypto-shorthash-siphash24-keybytes,
    crypto-sign,
    crypto-sign-bytes,
    crypto-sign-detached,
    crypto-sign-ed25519,
    crypto-sign-ed25519-bytes,
    crypto-sign-ed25519-detached,
    crypto-sign-ed25519-keypair,
    crypto-sign-ed25519-open,
    crypto-sign-ed25519-pk-to-curve25519,
    crypto-sign-ed25519-publickeybytes,
    crypto-sign-ed25519-secretkeybytes,
    crypto-sign-ed25519-seed-keypair,
    crypto-sign-ed25519-seedbytes,
    crypto-sign-ed25519-sk-to-curve25519,
    crypto-sign-ed25519-sk-to-pk,
    crypto-sign-ed25519-sk-to-seed,
    crypto-sign-ed25519-verify-detached,
    crypto-sign-edwards25519sha512batch,
    crypto-sign-edwards25519sha512batch-keypair,
    crypto-sign-edwards25519sha512batch-open,
    crypto-sign-keypair,
    crypto-sign-open,
    crypto-sign-primitive,
    crypto-sign-publickeybytes,
    crypto-sign-secretkeybytes,
    crypto-sign-seed-keypair,
    crypto-sign-seedbytes,
    crypto-sign-verify-detached,
    crypto-stream,
    crypto-stream-aes128ctr,
    crypto-stream-aes128ctr-afternm,
    crypto-stream-aes128ctr-beforenm,
    crypto-stream-aes128ctr-beforenmbytes,
    crypto-stream-aes128ctr-keybytes,
    crypto-stream-aes128ctr-noncebytes,
    crypto-stream-aes128ctr-xor,
    crypto-stream-aes128ctr-xor-afternm,
    crypto-stream-chacha20,
    crypto-stream-chacha20-ietf,
    crypto-stream-chacha20-ietf-noncebytes,
    crypto-stream-chacha20-ietf-xor,
    crypto-stream-chacha20-ietf-xor-ic,
    crypto-stream-chacha20-keybytes,
    crypto-stream-chacha20-noncebytes,
    crypto-stream-chacha20-xor,
    crypto-stream-chacha20-xor-ic,
    crypto-stream-keybytes,
    crypto-stream-noncebytes,
    crypto-stream-primitive,
    crypto-stream-salsa20,
    crypto-stream-salsa20-keybytes,
    crypto-stream-salsa20-noncebytes,
    crypto-stream-salsa20-xor,
    crypto-stream-salsa20-xor-ic,
    crypto-stream-salsa2012,
    crypto-stream-salsa2012-keybytes,
    crypto-stream-salsa2012-noncebytes,
    crypto-stream-salsa2012-xor,
    crypto-stream-salsa208,
    crypto-stream-salsa208-keybytes,
    crypto-stream-salsa208-noncebytes,
    crypto-stream-salsa208-xor,
    crypto-stream-xor,
    crypto-stream-xsalsa20,
    crypto-stream-xsalsa20-keybytes,
    crypto-stream-xsalsa20-noncebytes,
    crypto-stream-xsalsa20-xor,
    crypto-stream-xsalsa20-xor-ic,
    crypto-verify-16,
    crypto-verify-16-bytes,
    crypto-verify-32,
    crypto-verify-32-bytes,
    crypto-verify-64,
    crypto-verify-64-bytes,
    randombytes,
    randombytes-buf,
    randombytes-close,
    randombytes-implementation$buf,
    randombytes-implementation$buf-setter,
    randombytes-implementation$close,
    randombytes-implementation$close-setter,
    randombytes-implementation$implementation-name,
    randombytes-implementation$implementation-name-setter,
    randombytes-implementation$random,
    randombytes-implementation$random-setter,
    randombytes-implementation$stir,
    randombytes-implementation$stir-setter,
    randombytes-implementation$uniform,
    randombytes-implementation$uniform-setter,
    randombytes-implementation-name,
    randombytes-random,
    randombytes-set-implementation,
    randombytes-stir,
    randombytes-uniform,
    sodium-add,
    sodium-allocarray,
    sodium-bin2hex,
    sodium-compare,
    sodium-free,
    sodium-hex2bin,
    sodium-increment,
    sodium-init,
    sodium-is-zero,
    sodium-library-version-major,
    sodium-library-version-minor,
    sodium-malloc,
    sodium-memcmp,
    sodium-memzero,
    sodium-mlock,
    sodium-mprotect-noaccess,
    sodium-mprotect-readonly,
    sodium-mprotect-readwrite,
    sodium-munlock,
    sodium-runtime-has-aesni,
    sodium-runtime-has-avx,
    sodium-runtime-has-neon,
    sodium-runtime-has-pclmul,
    sodium-runtime-has-sse2,
    sodium-runtime-has-sse3,
    sodium-runtime-has-sse41,
    sodium-runtime-has-ssse3,
    sodium-version-string;
end module sodium;
