module: libsodium
synopsis: bindings for the sodium library
author: Bruce Mitchener, Jr.
copyright: See LICENSE file in this distribution.

define simple-C-mapped-subtype <C-buffer-offset> (<C-void*>)
  export-map <machine-word>, export-function: identity;
end;

define inline C-function sodium-init
  result res :: <C-signed-int>;
  c-name: "sodium_init";
end;

define inline C-function crypto-aead-aes256gcm-is-available
  result res :: <C-signed-int>;
  c-name: "crypto_aead_aes256gcm_is_available";
end;

define inline C-function crypto-aead-aes256gcm-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_aes256gcm_keybytes";
end;

define inline C-function crypto-aead-aes256gcm-nsecbytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_aes256gcm_nsecbytes";
end;

define inline C-function crypto-aead-aes256gcm-npubbytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_aes256gcm_npubbytes";
end;

define inline C-function crypto-aead-aes256gcm-abytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_aes256gcm_abytes";
end;

define C-pointer-type <unsigned-char*> => <C-unsigned-char>;
define constant <unsigned-char<@512>> = <unsigned-char*>;
define constant <crypto-aead-aes256gcm-state> = <unsigned-char<@512>>;

define inline C-function crypto-aead-aes256gcm-statebytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_aes256gcm_statebytes";
end;

define C-pointer-type <unsigned-long-long*> => <C-unsigned-long>;
define inline C-function crypto-aead-aes256gcm-encrypt
  input parameter c_ :: <unsigned-char*>;
  input parameter clen-p_ :: <unsigned-long-long*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter ad_ :: <unsigned-char*>;
  input parameter adlen_ :: <C-unsigned-long>;
  input parameter nsec_ :: <unsigned-char*>;
  input parameter npub_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_aead_aes256gcm_encrypt";
end;

define inline C-function crypto-aead-aes256gcm-decrypt
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen-p_ :: <unsigned-long-long*>;
  input parameter nsec_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter ad_ :: <unsigned-char*>;
  input parameter adlen_ :: <C-unsigned-long>;
  input parameter npub_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_aead_aes256gcm_decrypt";
end;

define C-pointer-type <unsigned-char<@512>*> => <unsigned-char<@512>>;
define inline C-function crypto-aead-aes256gcm-beforenm
  input parameter ctx-_ :: <unsigned-char<@512>*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_aead_aes256gcm_beforenm";
end;

define inline C-function crypto-aead-aes256gcm-encrypt-afternm
  input parameter c_ :: <unsigned-char*>;
  input parameter clen-p_ :: <unsigned-long-long*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter ad_ :: <unsigned-char*>;
  input parameter adlen_ :: <C-unsigned-long>;
  input parameter nsec_ :: <unsigned-char*>;
  input parameter npub_ :: <unsigned-char*>;
  input parameter ctx-_ :: <unsigned-char<@512>*>;
  result res :: <C-signed-int>;
  c-name: "crypto_aead_aes256gcm_encrypt_afternm";
end;

define inline C-function crypto-aead-aes256gcm-decrypt-afternm
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen-p_ :: <unsigned-long-long*>;
  input parameter nsec_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter ad_ :: <unsigned-char*>;
  input parameter adlen_ :: <C-unsigned-long>;
  input parameter npub_ :: <unsigned-char*>;
  input parameter ctx-_ :: <unsigned-char<@512>*>;
  result res :: <C-signed-int>;
  c-name: "crypto_aead_aes256gcm_decrypt_afternm";
end;

define constant $crypto-aead-aes256gcm-KEYBYTES = 32;

define constant $crypto-aead-aes256gcm-NSECBYTES = 0;

define constant $crypto-aead-aes256gcm-NPUBBYTES = 12;

define constant $crypto-aead-aes256gcm-ABYTES = 16;

define inline C-function crypto-aead-chacha20poly1305-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_chacha20poly1305_keybytes";
end;

define inline C-function crypto-aead-chacha20poly1305-nsecbytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_chacha20poly1305_nsecbytes";
end;

define inline C-function crypto-aead-chacha20poly1305-npubbytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_chacha20poly1305_npubbytes";
end;

define inline C-function crypto-aead-chacha20poly1305-abytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_chacha20poly1305_abytes";
end;

define inline C-function crypto-aead-chacha20poly1305-encrypt
  input parameter c_ :: <unsigned-char*>;
  input parameter clen-p_ :: <unsigned-long-long*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter ad_ :: <unsigned-char*>;
  input parameter adlen_ :: <C-unsigned-long>;
  input parameter nsec_ :: <unsigned-char*>;
  input parameter npub_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_aead_chacha20poly1305_encrypt";
end;

define inline C-function crypto-aead-chacha20poly1305-decrypt
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen-p_ :: <unsigned-long-long*>;
  input parameter nsec_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter ad_ :: <unsigned-char*>;
  input parameter adlen_ :: <C-unsigned-long>;
  input parameter npub_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_aead_chacha20poly1305_decrypt";
end;

define inline C-function crypto-aead-chacha20poly1305-ietf-npubbytes
  result res :: <C-size-t>;
  c-name: "crypto_aead_chacha20poly1305_ietf_npubbytes";
end;

define inline C-function crypto-aead-chacha20poly1305-ietf-encrypt
  input parameter c_ :: <unsigned-char*>;
  input parameter clen-p_ :: <unsigned-long-long*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter ad_ :: <unsigned-char*>;
  input parameter adlen_ :: <C-unsigned-long>;
  input parameter nsec_ :: <unsigned-char*>;
  input parameter npub_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_aead_chacha20poly1305_ietf_encrypt";
end;

define inline C-function crypto-aead-chacha20poly1305-ietf-decrypt
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen-p_ :: <unsigned-long-long*>;
  input parameter nsec_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter ad_ :: <unsigned-char*>;
  input parameter adlen_ :: <C-unsigned-long>;
  input parameter npub_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_aead_chacha20poly1305_ietf_decrypt";
end;

define constant $crypto-aead-chacha20poly1305-KEYBYTES = 32;

define constant $crypto-aead-chacha20poly1305-NSECBYTES = 0;

define constant $crypto-aead-chacha20poly1305-NPUBBYTES = 8;

define constant $crypto-aead-chacha20poly1305-ABYTES = 16;

define constant $crypto-aead-chacha20poly1305-IETF-NPUBBYTES = 12;

define inline C-function crypto-auth-bytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_bytes";
end;

define inline C-function crypto-auth-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_keybytes";
end;

define inline C-function crypto-auth-primitive
  result res :: <C-string>;
  c-name: "crypto_auth_primitive";
end;

define inline C-function %crypto-auth
  input parameter out_ :: <C-buffer-offset>;
  input parameter in_ :: <C-buffer-offset>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <C-buffer-offset>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth";
end;

define inline C-function %crypto-auth-verify
  input parameter h_ :: <C-buffer-offset>;
  input parameter in_ :: <C-buffer-offset>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <C-buffer-offset>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_verify";
end;

define constant $crypto-auth-BYTES = 32;

define constant $crypto-auth-KEYBYTES = 32;

define constant $crypto-auth-PRIMITIVE = "hmacsha512256";

define inline C-function crypto-auth-hmacsha256-bytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_hmacsha256_bytes";
end;

define inline C-function crypto-auth-hmacsha256-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_hmacsha256_keybytes";
end;

define inline C-function %crypto-auth-hmacsha256
  input parameter out_ :: <C-buffer-offset>;
  input parameter in_ :: <C-buffer-offset>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <C-buffer-offset>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha256";
end;

define inline C-function %crypto-auth-hmacsha256-verify
  input parameter h_ :: <C-buffer-offset>;
  input parameter in_ :: <C-buffer-offset>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <C-buffer-offset>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha256_verify";
end;

define C-struct <crypto-hash-sha256-state>
  sealed array slot crypto-hash-sha256-state$state :: <C-unsigned-int>, length: 8;
  sealed slot crypto-hash-sha256-state$count :: <C-unsigned-long>;
  sealed array slot crypto-hash-sha256-state$buf :: <C-unsigned-char>, length: 64;
end;

define C-struct <crypto-auth-hmacsha256-state>
  sealed slot crypto-auth-hmacsha256-state$ictx :: <crypto-hash-sha256-state>;
  sealed slot crypto-auth-hmacsha256-state$octx :: <crypto-hash-sha256-state>;
end;

define inline C-function crypto-auth-hmacsha256-statebytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_hmacsha256_statebytes";
end;

define C-pointer-type <crypto-auth-hmacsha256-state*> => <crypto-auth-hmacsha256-state>;
define inline C-function crypto-auth-hmacsha256-init
  input parameter state_ :: <crypto-auth-hmacsha256-state*>;
  input parameter key_ :: <unsigned-char*>;
  input parameter keylen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha256_init";
end;

define inline C-function crypto-auth-hmacsha256-update
  input parameter state_ :: <crypto-auth-hmacsha256-state*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha256_update";
end;

define inline C-function crypto-auth-hmacsha256-final
  input parameter state_ :: <crypto-auth-hmacsha256-state*>;
  input parameter out_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha256_final";
end;

define constant $crypto-auth-hmacsha256-BYTES = 32;

define constant $crypto-auth-hmacsha256-KEYBYTES = 32;

define inline C-function crypto-auth-hmacsha512-bytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_hmacsha512_bytes";
end;

define inline C-function crypto-auth-hmacsha512-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_hmacsha512_keybytes";
end;

define inline C-function %crypto-auth-hmacsha512
  input parameter out_ :: <C-buffer-offset>;
  input parameter in_ :: <C-buffer-offset>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <C-buffer-offset>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512";
end;

define inline C-function %crypto-auth-hmacsha512-verify
  input parameter h_ :: <C-buffer-offset>;
  input parameter in_ :: <C-buffer-offset>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <C-buffer-offset>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512_verify";
end;

define C-struct <crypto-hash-sha512-state>
  sealed array slot crypto-hash-sha512-state$state :: <C-unsigned-long>, length: 8;
  sealed array slot crypto-hash-sha512-state$count :: <C-unsigned-long>, length: 2;
  sealed array slot crypto-hash-sha512-state$buf :: <C-unsigned-char>, length: 128;
end;

define C-struct <crypto-auth-hmacsha512-state>
  sealed slot crypto-auth-hmacsha512-state$ictx :: <crypto-hash-sha512-state>;
  sealed slot crypto-auth-hmacsha512-state$octx :: <crypto-hash-sha512-state>;
end;

define inline C-function crypto-auth-hmacsha512-statebytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_hmacsha512_statebytes";
end;

define C-pointer-type <crypto-auth-hmacsha512-state*> => <crypto-auth-hmacsha512-state>;
define inline C-function crypto-auth-hmacsha512-init
  input parameter state_ :: <crypto-auth-hmacsha512-state*>;
  input parameter key_ :: <unsigned-char*>;
  input parameter keylen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512_init";
end;

define inline C-function crypto-auth-hmacsha512-update
  input parameter state_ :: <crypto-auth-hmacsha512-state*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512_update";
end;

define inline C-function crypto-auth-hmacsha512-final
  input parameter state_ :: <crypto-auth-hmacsha512-state*>;
  input parameter out_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512_final";
end;

define constant $crypto-auth-hmacsha512-BYTES = 64;

define constant $crypto-auth-hmacsha512-KEYBYTES = 32;

define inline C-function crypto-auth-hmacsha512256-bytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_hmacsha512256_bytes";
end;

define inline C-function crypto-auth-hmacsha512256-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_hmacsha512256_keybytes";
end;

define inline C-function %crypto-auth-hmacsha512256
  input parameter out_ :: <C-buffer-offset>;
  input parameter in_ :: <C-buffer-offset>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <C-buffer-offset>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512256";
end;

define inline C-function %crypto-auth-hmacsha512256-verify
  input parameter h_ :: <C-buffer-offset>;
  input parameter in_ :: <C-buffer-offset>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <C-buffer-offset>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512256_verify";
end;

define constant <crypto-auth-hmacsha512256-state> = <crypto-auth-hmacsha512-state>;

define inline C-function crypto-auth-hmacsha512256-statebytes
  result res :: <C-size-t>;
  c-name: "crypto_auth_hmacsha512256_statebytes";
end;

define inline C-function crypto-auth-hmacsha512256-init
  input parameter state_ :: <crypto-auth-hmacsha512-state*>;
  input parameter key_ :: <unsigned-char*>;
  input parameter keylen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512256_init";
end;

define inline C-function crypto-auth-hmacsha512256-update
  input parameter state_ :: <crypto-auth-hmacsha512-state*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512256_update";
end;

define inline C-function crypto-auth-hmacsha512256-final
  input parameter state_ :: <crypto-auth-hmacsha512-state*>;
  input parameter out_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_auth_hmacsha512256_final";
end;

define constant $crypto-auth-hmacsha512256-BYTES = 32;

define constant $crypto-auth-hmacsha512256-KEYBYTES = 32;

define inline C-function crypto-box-seedbytes
  result res :: <C-size-t>;
  c-name: "crypto_box_seedbytes";
end;

define inline C-function crypto-box-publickeybytes
  result res :: <C-size-t>;
  c-name: "crypto_box_publickeybytes";
end;

define inline C-function crypto-box-secretkeybytes
  result res :: <C-size-t>;
  c-name: "crypto_box_secretkeybytes";
end;

define inline C-function crypto-box-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_box_noncebytes";
end;

define inline C-function crypto-box-macbytes
  result res :: <C-size-t>;
  c-name: "crypto_box_macbytes";
end;

define inline C-function crypto-box-primitive
  result res :: <C-string>;
  c-name: "crypto_box_primitive";
end;

define inline C-function crypto-box-seed-keypair
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  input parameter seed_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_seed_keypair";
end;

define inline C-function crypto-box-keypair
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_keypair";
end;

define inline C-function crypto-box-easy
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_easy";
end;

define inline C-function crypto-box-open-easy
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_open_easy";
end;

define inline C-function crypto-box-detached
  input parameter c_ :: <unsigned-char*>;
  input parameter mac_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_detached";
end;

define inline C-function crypto-box-open-detached
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter mac_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_open_detached";
end;

define inline C-function crypto-box-beforenmbytes
  result res :: <C-size-t>;
  c-name: "crypto_box_beforenmbytes";
end;

define inline C-function crypto-box-beforenm
  input parameter k_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_beforenm";
end;

define inline C-function crypto-box-easy-afternm
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_easy_afternm";
end;

define inline C-function crypto-box-open-easy-afternm
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_open_easy_afternm";
end;

define inline C-function crypto-box-detached-afternm
  input parameter c_ :: <unsigned-char*>;
  input parameter mac_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_detached_afternm";
end;

define inline C-function crypto-box-open-detached-afternm
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter mac_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_open_detached_afternm";
end;

define inline C-function crypto-box-sealbytes
  result res :: <C-size-t>;
  c-name: "crypto_box_sealbytes";
end;

define inline C-function crypto-box-seal
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter pk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_seal";
end;

define inline C-function crypto-box-seal-open
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_seal_open";
end;

define inline C-function crypto-box-zerobytes
  result res :: <C-size-t>;
  c-name: "crypto_box_zerobytes";
end;

define inline C-function crypto-box-boxzerobytes
  result res :: <C-size-t>;
  c-name: "crypto_box_boxzerobytes";
end;

define inline C-function crypto-box
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box";
end;

define inline C-function crypto-box-open
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_open";
end;

define inline C-function crypto-box-afternm
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_afternm";
end;

define inline C-function crypto-box-open-afternm
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_open_afternm";
end;

define constant $crypto-box-SEEDBYTES = 32;

define constant $crypto-box-PUBLICKEYBYTES = 32;

define constant $crypto-box-SECRETKEYBYTES = 32;

define constant $crypto-box-NONCEBYTES = 24;

define constant $crypto-box-MACBYTES = 16;

define constant $crypto-box-PRIMITIVE = "curve25519xsalsa20poly1305";

define constant $crypto-box-BEFORENMBYTES = 32;

define constant $crypto-box-SEALBYTES = 48;

define constant $crypto-box-ZEROBYTES = 32;

define constant $crypto-box-BOXZEROBYTES = 16;

define inline C-function crypto-box-curve25519xsalsa20poly1305-seedbytes
  result res :: <C-size-t>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_seedbytes";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-publickeybytes
  result res :: <C-size-t>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_publickeybytes";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-secretkeybytes
  result res :: <C-size-t>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_secretkeybytes";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-beforenmbytes
  result res :: <C-size-t>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_beforenmbytes";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_noncebytes";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-zerobytes
  result res :: <C-size-t>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_zerobytes";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-boxzerobytes
  result res :: <C-size-t>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_boxzerobytes";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-macbytes
  result res :: <C-size-t>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_macbytes";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_curve25519xsalsa20poly1305";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-open
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_open";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-seed-keypair
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  input parameter seed_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_seed_keypair";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-keypair
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_keypair";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-beforenm
  input parameter k_ :: <unsigned-char*>;
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_beforenm";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-afternm
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_afternm";
end;

define inline C-function crypto-box-curve25519xsalsa20poly1305-open-afternm
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_box_curve25519xsalsa20poly1305_open_afternm";
end;

define constant $crypto-box-curve25519xsalsa20poly1305-SEEDBYTES = 32;

define constant $crypto-box-curve25519xsalsa20poly1305-PUBLICKEYBYTES = 32;

define constant $crypto-box-curve25519xsalsa20poly1305-SECRETKEYBYTES = 32;

define constant $crypto-box-curve25519xsalsa20poly1305-BEFORENMBYTES = 32;

define constant $crypto-box-curve25519xsalsa20poly1305-NONCEBYTES = 24;

define constant $crypto-box-curve25519xsalsa20poly1305-ZEROBYTES = 32;

define constant $crypto-box-curve25519xsalsa20poly1305-BOXZEROBYTES = 16;

define constant $crypto-box-curve25519xsalsa20poly1305-MACBYTES = 16;

define inline C-function crypto-core-hsalsa20-outputbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_hsalsa20_outputbytes";
end;

define inline C-function crypto-core-hsalsa20-inputbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_hsalsa20_inputbytes";
end;

define inline C-function crypto-core-hsalsa20-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_core_hsalsa20_keybytes";
end;

define inline C-function crypto-core-hsalsa20-constbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_hsalsa20_constbytes";
end;

define inline C-function crypto-core-hsalsa20
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_core_hsalsa20";
end;

define constant $crypto-core-hsalsa20-OUTPUTBYTES = 32;

define constant $crypto-core-hsalsa20-INPUTBYTES = 16;

define constant $crypto-core-hsalsa20-KEYBYTES = 32;

define constant $crypto-core-hsalsa20-CONSTBYTES = 16;

define inline C-function crypto-core-salsa20-outputbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa20_outputbytes";
end;

define inline C-function crypto-core-salsa20-inputbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa20_inputbytes";
end;

define inline C-function crypto-core-salsa20-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa20_keybytes";
end;

define inline C-function crypto-core-salsa20-constbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa20_constbytes";
end;

define inline C-function crypto-core-salsa20
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_core_salsa20";
end;

define constant $crypto-core-salsa20-OUTPUTBYTES = 64;

define constant $crypto-core-salsa20-INPUTBYTES = 16;

define constant $crypto-core-salsa20-KEYBYTES = 32;

define constant $crypto-core-salsa20-CONSTBYTES = 16;

define inline C-function crypto-core-salsa2012-outputbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa2012_outputbytes";
end;

define inline C-function crypto-core-salsa2012-inputbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa2012_inputbytes";
end;

define inline C-function crypto-core-salsa2012-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa2012_keybytes";
end;

define inline C-function crypto-core-salsa2012-constbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa2012_constbytes";
end;

define inline C-function crypto-core-salsa2012
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_core_salsa2012";
end;

define constant $crypto-core-salsa2012-OUTPUTBYTES = 64;

define constant $crypto-core-salsa2012-INPUTBYTES = 16;

define constant $crypto-core-salsa2012-KEYBYTES = 32;

define constant $crypto-core-salsa2012-CONSTBYTES = 16;

define inline C-function crypto-core-salsa208-outputbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa208_outputbytes";
end;

define inline C-function crypto-core-salsa208-inputbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa208_inputbytes";
end;

define inline C-function crypto-core-salsa208-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa208_keybytes";
end;

define inline C-function crypto-core-salsa208-constbytes
  result res :: <C-size-t>;
  c-name: "crypto_core_salsa208_constbytes";
end;

define inline C-function crypto-core-salsa208
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_core_salsa208";
end;

define constant $crypto-core-salsa208-OUTPUTBYTES = 64;

define constant $crypto-core-salsa208-INPUTBYTES = 16;

define constant $crypto-core-salsa208-KEYBYTES = 32;

define constant $crypto-core-salsa208-CONSTBYTES = 16;

define inline C-function crypto-generichash-bytes-min
  result res :: <C-size-t>;
  c-name: "crypto_generichash_bytes_min";
end;

define inline C-function crypto-generichash-bytes-max
  result res :: <C-size-t>;
  c-name: "crypto_generichash_bytes_max";
end;

define inline C-function crypto-generichash-bytes
  result res :: <C-size-t>;
  c-name: "crypto_generichash_bytes";
end;

define inline C-function crypto-generichash-keybytes-min
  result res :: <C-size-t>;
  c-name: "crypto_generichash_keybytes_min";
end;

define inline C-function crypto-generichash-keybytes-max
  result res :: <C-size-t>;
  c-name: "crypto_generichash_keybytes_max";
end;

define inline C-function crypto-generichash-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_generichash_keybytes";
end;

define inline C-function crypto-generichash-primitive
  result res :: <C-string>;
  c-name: "crypto_generichash_primitive";
end;

define C-struct <crypto-generichash-blake2b-state>
  sealed array slot crypto-generichash-blake2b-state$h :: <C-unsigned-long>, length: 8;
  sealed array slot crypto-generichash-blake2b-state$t :: <C-unsigned-long>, length: 2;
  sealed array slot crypto-generichash-blake2b-state$f :: <C-unsigned-long>, length: 2;
  sealed array slot crypto-generichash-blake2b-state$buf :: <C-unsigned-char>, length: 256;
  sealed slot crypto-generichash-blake2b-state$buflen :: <C-size-t>;
  sealed slot crypto-generichash-blake2b-state$last-node :: <C-unsigned-char>;
end;

define constant <crypto-generichash-state> = <crypto-generichash-blake2b-state>;

define inline C-function crypto-generichash-statebytes
  result res :: <C-size-t>;
  c-name: "crypto_generichash_statebytes";
end;

define inline C-function crypto-generichash
  input parameter out_ :: <unsigned-char*>;
  input parameter outlen_ :: <C-size-t>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter key_ :: <unsigned-char*>;
  input parameter keylen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash";
end;

define C-pointer-type <crypto-generichash-blake2b-state*> => <crypto-generichash-blake2b-state>;
define inline C-function crypto-generichash-init
  input parameter state_ :: <crypto-generichash-blake2b-state*>;
  input parameter key_ :: <unsigned-char*>;
  input parameter keylen_ :: <C-size-t>;
  input parameter outlen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash_init";
end;

define inline C-function crypto-generichash-update
  input parameter state_ :: <crypto-generichash-blake2b-state*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash_update";
end;

define inline C-function crypto-generichash-final
  input parameter state_ :: <crypto-generichash-blake2b-state*>;
  input parameter out_ :: <unsigned-char*>;
  input parameter outlen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash_final";
end;

define constant $crypto-generichash-BYTES-MIN = 16;

define constant $crypto-generichash-BYTES-MAX = 64;

define constant $crypto-generichash-BYTES = 32;

define constant $crypto-generichash-KEYBYTES-MIN = 16;

define constant $crypto-generichash-KEYBYTES-MAX = 64;

define constant $crypto-generichash-KEYBYTES = 32;

define constant $crypto-generichash-PRIMITIVE = "blake2b";

define inline C-function crypto-generichash-blake2b-bytes-min
  result res :: <C-size-t>;
  c-name: "crypto_generichash_blake2b_bytes_min";
end;

define inline C-function crypto-generichash-blake2b-bytes-max
  result res :: <C-size-t>;
  c-name: "crypto_generichash_blake2b_bytes_max";
end;

define inline C-function crypto-generichash-blake2b-bytes
  result res :: <C-size-t>;
  c-name: "crypto_generichash_blake2b_bytes";
end;

define inline C-function crypto-generichash-blake2b-keybytes-min
  result res :: <C-size-t>;
  c-name: "crypto_generichash_blake2b_keybytes_min";
end;

define inline C-function crypto-generichash-blake2b-keybytes-max
  result res :: <C-size-t>;
  c-name: "crypto_generichash_blake2b_keybytes_max";
end;

define inline C-function crypto-generichash-blake2b-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_generichash_blake2b_keybytes";
end;

define inline C-function crypto-generichash-blake2b-saltbytes
  result res :: <C-size-t>;
  c-name: "crypto_generichash_blake2b_saltbytes";
end;

define inline C-function crypto-generichash-blake2b-personalbytes
  result res :: <C-size-t>;
  c-name: "crypto_generichash_blake2b_personalbytes";
end;

define inline C-function crypto-generichash-blake2b
  input parameter out_ :: <unsigned-char*>;
  input parameter outlen_ :: <C-size-t>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter key_ :: <unsigned-char*>;
  input parameter keylen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash_blake2b";
end;

define inline C-function crypto-generichash-blake2b-salt-personal
  input parameter out_ :: <unsigned-char*>;
  input parameter outlen_ :: <C-size-t>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter key_ :: <unsigned-char*>;
  input parameter keylen_ :: <C-size-t>;
  input parameter salt_ :: <unsigned-char*>;
  input parameter personal_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash_blake2b_salt_personal";
end;

define inline C-function crypto-generichash-blake2b-init
  input parameter state_ :: <crypto-generichash-blake2b-state*>;
  input parameter key_ :: <unsigned-char*>;
  input parameter keylen_ :: <C-size-t>;
  input parameter outlen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash_blake2b_init";
end;

define inline C-function crypto-generichash-blake2b-init-salt-personal
  input parameter state_ :: <crypto-generichash-blake2b-state*>;
  input parameter key_ :: <unsigned-char*>;
  input parameter keylen_ :: <C-size-t>;
  input parameter outlen_ :: <C-size-t>;
  input parameter salt_ :: <unsigned-char*>;
  input parameter personal_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash_blake2b_init_salt_personal";
end;

define inline C-function crypto-generichash-blake2b-update
  input parameter state_ :: <crypto-generichash-blake2b-state*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash_blake2b_update";
end;

define inline C-function crypto-generichash-blake2b-final
  input parameter state_ :: <crypto-generichash-blake2b-state*>;
  input parameter out_ :: <unsigned-char*>;
  input parameter outlen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_generichash_blake2b_final";
end;

define constant $crypto-generichash-blake2b-BYTES-MIN = 16;

define constant $crypto-generichash-blake2b-BYTES-MAX = 64;

define constant $crypto-generichash-blake2b-BYTES = 32;

define constant $crypto-generichash-blake2b-KEYBYTES-MIN = 16;

define constant $crypto-generichash-blake2b-KEYBYTES-MAX = 64;

define constant $crypto-generichash-blake2b-KEYBYTES = 32;

define constant $crypto-generichash-blake2b-SALTBYTES = 16;

define constant $crypto-generichash-blake2b-PERSONALBYTES = 16;

define inline C-function crypto-hash-bytes
  result res :: <C-size-t>;
  c-name: "crypto_hash_bytes";
end;

define inline C-function crypto-hash
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_hash";
end;

define inline C-function crypto-hash-primitive
  result res :: <C-string>;
  c-name: "crypto_hash_primitive";
end;

define constant $crypto-hash-BYTES = 64;

define constant $crypto-hash-PRIMITIVE = "sha512";

define inline C-function crypto-hash-sha256-statebytes
  result res :: <C-size-t>;
  c-name: "crypto_hash_sha256_statebytes";
end;

define inline C-function crypto-hash-sha256-bytes
  result res :: <C-size-t>;
  c-name: "crypto_hash_sha256_bytes";
end;

define inline C-function crypto-hash-sha256
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_hash_sha256";
end;

define C-pointer-type <crypto-hash-sha256-state*> => <crypto-hash-sha256-state>;
define inline C-function crypto-hash-sha256-init
  input parameter state_ :: <crypto-hash-sha256-state*>;
  result res :: <C-signed-int>;
  c-name: "crypto_hash_sha256_init";
end;

define inline C-function crypto-hash-sha256-update
  input parameter state_ :: <crypto-hash-sha256-state*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_hash_sha256_update";
end;

define inline C-function crypto-hash-sha256-final
  input parameter state_ :: <crypto-hash-sha256-state*>;
  input parameter out_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_hash_sha256_final";
end;

define constant $crypto-hash-sha256-BYTES = 32;

define inline C-function crypto-hash-sha512-statebytes
  result res :: <C-size-t>;
  c-name: "crypto_hash_sha512_statebytes";
end;

define inline C-function crypto-hash-sha512-bytes
  result res :: <C-size-t>;
  c-name: "crypto_hash_sha512_bytes";
end;

define inline C-function crypto-hash-sha512
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_hash_sha512";
end;

define C-pointer-type <crypto-hash-sha512-state*> => <crypto-hash-sha512-state>;
define inline C-function crypto-hash-sha512-init
  input parameter state_ :: <crypto-hash-sha512-state*>;
  result res :: <C-signed-int>;
  c-name: "crypto_hash_sha512_init";
end;

define inline C-function crypto-hash-sha512-update
  input parameter state_ :: <crypto-hash-sha512-state*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_hash_sha512_update";
end;

define inline C-function crypto-hash-sha512-final
  input parameter state_ :: <crypto-hash-sha512-state*>;
  input parameter out_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_hash_sha512_final";
end;

define constant $crypto-hash-sha512-BYTES = 64;

define C-struct <crypto-onetimeauth-poly1305-state>
  sealed array slot crypto-onetimeauth-poly1305-state$opaque :: <C-unsigned-char>, length: 256;
end;

define constant <crypto-onetimeauth-state> = <crypto-onetimeauth-poly1305-state>;

define inline C-function crypto-onetimeauth-statebytes
  result res :: <C-size-t>;
  c-name: "crypto_onetimeauth_statebytes";
end;

define inline C-function crypto-onetimeauth-bytes
  result res :: <C-size-t>;
  c-name: "crypto_onetimeauth_bytes";
end;

define inline C-function crypto-onetimeauth-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_onetimeauth_keybytes";
end;

define inline C-function crypto-onetimeauth-primitive
  result res :: <C-string>;
  c-name: "crypto_onetimeauth_primitive";
end;

define inline C-function crypto-onetimeauth
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth";
end;

define inline C-function crypto-onetimeauth-verify
  input parameter h_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth_verify";
end;

define C-pointer-type <crypto-onetimeauth-poly1305-state*> => <crypto-onetimeauth-poly1305-state>;
define inline C-function crypto-onetimeauth-init
  input parameter state_ :: <crypto-onetimeauth-poly1305-state*>;
  input parameter key_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth_init";
end;

define inline C-function crypto-onetimeauth-update
  input parameter state_ :: <crypto-onetimeauth-poly1305-state*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth_update";
end;

define inline C-function crypto-onetimeauth-final
  input parameter state_ :: <crypto-onetimeauth-poly1305-state*>;
  input parameter out_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth_final";
end;

define constant $crypto-onetimeauth-BYTES = 16;

define constant $crypto-onetimeauth-KEYBYTES = 32;

define constant $crypto-onetimeauth-PRIMITIVE = "poly1305";

define inline C-function crypto-onetimeauth-poly1305-bytes
  result res :: <C-size-t>;
  c-name: "crypto_onetimeauth_poly1305_bytes";
end;

define inline C-function crypto-onetimeauth-poly1305-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_onetimeauth_poly1305_keybytes";
end;

define inline C-function crypto-onetimeauth-poly1305
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth_poly1305";
end;

define inline C-function crypto-onetimeauth-poly1305-verify
  input parameter h_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth_poly1305_verify";
end;

define inline C-function crypto-onetimeauth-poly1305-init
  input parameter state_ :: <crypto-onetimeauth-poly1305-state*>;
  input parameter key_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth_poly1305_init";
end;

define inline C-function crypto-onetimeauth-poly1305-update
  input parameter state_ :: <crypto-onetimeauth-poly1305-state*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth_poly1305_update";
end;

define inline C-function crypto-onetimeauth-poly1305-final
  input parameter state_ :: <crypto-onetimeauth-poly1305-state*>;
  input parameter out_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_onetimeauth_poly1305_final";
end;

define constant $crypto-onetimeauth-poly1305-BYTES = 16;

define constant $crypto-onetimeauth-poly1305-KEYBYTES = 32;

define inline C-function crypto-pwhash-scryptsalsa208sha256-saltbytes
  result res :: <C-size-t>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_saltbytes";
end;

define inline C-function crypto-pwhash-scryptsalsa208sha256-strbytes
  result res :: <C-size-t>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_strbytes";
end;

define inline C-function crypto-pwhash-scryptsalsa208sha256-strprefix
  result res :: <C-string>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_strprefix";
end;

define inline C-function crypto-pwhash-scryptsalsa208sha256-opslimit-interactive
  result res :: <C-size-t>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_opslimit_interactive";
end;

define inline C-function crypto-pwhash-scryptsalsa208sha256-memlimit-interactive
  result res :: <C-size-t>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_memlimit_interactive";
end;

define inline C-function crypto-pwhash-scryptsalsa208sha256-opslimit-sensitive
  result res :: <C-size-t>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive";
end;

define inline C-function crypto-pwhash-scryptsalsa208sha256-memlimit-sensitive
  result res :: <C-size-t>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive";
end;

define inline C-function crypto-pwhash-scryptsalsa208sha256
  input parameter out_ :: <unsigned-char*>;
  input parameter outlen_ :: <C-unsigned-long>;
  input parameter passwd_ :: <C-string>;
  input parameter passwdlen_ :: <C-unsigned-long>;
  input parameter salt_ :: <unsigned-char*>;
  input parameter opslimit_ :: <C-unsigned-long>;
  input parameter memlimit_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_pwhash_scryptsalsa208sha256";
end;

define constant <char<@102>> = <C-string>;
define inline C-function crypto-pwhash-scryptsalsa208sha256-str
  input parameter out_ :: <char<@102>>;
  input parameter passwd_ :: <C-string>;
  input parameter passwdlen_ :: <C-unsigned-long>;
  input parameter opslimit_ :: <C-unsigned-long>;
  input parameter memlimit_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_str";
end;

define inline C-function crypto-pwhash-scryptsalsa208sha256-str-verify
  input parameter str_ :: <char<@102>>;
  input parameter passwd_ :: <C-string>;
  input parameter passwdlen_ :: <C-unsigned-long>;
  result res :: <C-signed-int>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_str_verify";
end;

define constant <uint64-t> = <C-unsigned-long>;

define constant <uint32-t> = <C-unsigned-int>;

define inline C-function crypto-pwhash-scryptsalsa208sha256-ll
  input parameter passwd_ :: <unsigned-char*>;
  input parameter passwdlen_ :: <C-size-t>;
  input parameter salt_ :: <unsigned-char*>;
  input parameter saltlen_ :: <C-size-t>;
  input parameter N_ :: <uint64-t>;
  input parameter r_ :: <uint32-t>;
  input parameter p_ :: <uint32-t>;
  input parameter buf_ :: <unsigned-char*>;
  input parameter buflen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "crypto_pwhash_scryptsalsa208sha256_ll";
end;

define constant $crypto-pwhash-scryptsalsa208sha256-SALTBYTES = 32;

define constant $crypto-pwhash-scryptsalsa208sha256-STRBYTES = 102;

define constant $crypto-pwhash-scryptsalsa208sha256-STRPREFIX = "$7$";

define constant $crypto-pwhash-scryptsalsa208sha256-OPSLIMIT-INTERACTIVE = 524288;

define constant $crypto-pwhash-scryptsalsa208sha256-MEMLIMIT-INTERACTIVE = 16777216;

define constant $crypto-pwhash-scryptsalsa208sha256-OPSLIMIT-SENSITIVE = 33554432;

define constant $crypto-pwhash-scryptsalsa208sha256-MEMLIMIT-SENSITIVE = 0;

define inline C-function crypto-scalarmult-bytes
  result res :: <C-size-t>;
  c-name: "crypto_scalarmult_bytes";
end;

define inline C-function crypto-scalarmult-scalarbytes
  result res :: <C-size-t>;
  c-name: "crypto_scalarmult_scalarbytes";
end;

define inline C-function crypto-scalarmult-primitive
  result res :: <C-string>;
  c-name: "crypto_scalarmult_primitive";
end;

define inline C-function crypto-scalarmult-base
  input parameter q_ :: <unsigned-char*>;
  input parameter n_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_scalarmult_base";
end;

define inline C-function crypto-scalarmult
  input parameter q_ :: <unsigned-char*>;
  input parameter n_ :: <unsigned-char*>;
  input parameter p_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_scalarmult";
end;

define constant $crypto-scalarmult-BYTES = 32;

define constant $crypto-scalarmult-SCALARBYTES = 32;

define constant $crypto-scalarmult-PRIMITIVE = "curve25519";

define inline C-function crypto-scalarmult-curve25519-bytes
  result res :: <C-size-t>;
  c-name: "crypto_scalarmult_curve25519_bytes";
end;

define inline C-function crypto-scalarmult-curve25519-scalarbytes
  result res :: <C-size-t>;
  c-name: "crypto_scalarmult_curve25519_scalarbytes";
end;

define inline C-function crypto-scalarmult-curve25519
  input parameter q_ :: <unsigned-char*>;
  input parameter n_ :: <unsigned-char*>;
  input parameter p_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_scalarmult_curve25519";
end;

define inline C-function crypto-scalarmult-curve25519-base
  input parameter q_ :: <unsigned-char*>;
  input parameter n_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_scalarmult_curve25519_base";
end;

define constant $crypto-scalarmult-curve25519-BYTES = 32;

define constant $crypto-scalarmult-curve25519-SCALARBYTES = 32;

define inline C-function crypto-secretbox-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_keybytes";
end;

define inline C-function crypto-secretbox-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_noncebytes";
end;

define inline C-function crypto-secretbox-macbytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_macbytes";
end;

define inline C-function crypto-secretbox-primitive
  result res :: <C-string>;
  c-name: "crypto_secretbox_primitive";
end;

define inline C-function crypto-secretbox-easy
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_secretbox_easy";
end;

define inline C-function crypto-secretbox-open-easy
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_secretbox_open_easy";
end;

define inline C-function crypto-secretbox-detached
  input parameter c_ :: <unsigned-char*>;
  input parameter mac_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_secretbox_detached";
end;

define inline C-function crypto-secretbox-open-detached
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter mac_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_secretbox_open_detached";
end;

define inline C-function crypto-secretbox-zerobytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_zerobytes";
end;

define inline C-function crypto-secretbox-boxzerobytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_boxzerobytes";
end;

define inline C-function crypto-secretbox
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_secretbox";
end;

define inline C-function crypto-secretbox-open
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_secretbox_open";
end;

define constant $crypto-secretbox-KEYBYTES = 32;

define constant $crypto-secretbox-NONCEBYTES = 24;

define constant $crypto-secretbox-MACBYTES = 16;

define constant $crypto-secretbox-PRIMITIVE = "xsalsa20poly1305";

define constant $crypto-secretbox-ZEROBYTES = 32;

define constant $crypto-secretbox-BOXZEROBYTES = 16;

define inline C-function crypto-secretbox-xsalsa20poly1305-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_xsalsa20poly1305_keybytes";
end;

define inline C-function crypto-secretbox-xsalsa20poly1305-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_xsalsa20poly1305_noncebytes";
end;

define inline C-function crypto-secretbox-xsalsa20poly1305-zerobytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_xsalsa20poly1305_zerobytes";
end;

define inline C-function crypto-secretbox-xsalsa20poly1305-boxzerobytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_xsalsa20poly1305_boxzerobytes";
end;

define inline C-function crypto-secretbox-xsalsa20poly1305-macbytes
  result res :: <C-size-t>;
  c-name: "crypto_secretbox_xsalsa20poly1305_macbytes";
end;

define inline C-function crypto-secretbox-xsalsa20poly1305
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_secretbox_xsalsa20poly1305";
end;

define inline C-function crypto-secretbox-xsalsa20poly1305-open
  input parameter m_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_secretbox_xsalsa20poly1305_open";
end;

define constant $crypto-secretbox-xsalsa20poly1305-KEYBYTES = 32;

define constant $crypto-secretbox-xsalsa20poly1305-NONCEBYTES = 24;

define constant $crypto-secretbox-xsalsa20poly1305-ZEROBYTES = 32;

define constant $crypto-secretbox-xsalsa20poly1305-BOXZEROBYTES = 16;

define constant $crypto-secretbox-xsalsa20poly1305-MACBYTES = 16;

define inline C-function crypto-shorthash-bytes
  result res :: <C-size-t>;
  c-name: "crypto_shorthash_bytes";
end;

define inline C-function crypto-shorthash-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_shorthash_keybytes";
end;

define inline C-function crypto-shorthash-primitive
  result res :: <C-string>;
  c-name: "crypto_shorthash_primitive";
end;

define inline C-function crypto-shorthash
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_shorthash";
end;

define constant $crypto-shorthash-BYTES = 8;

define constant $crypto-shorthash-KEYBYTES = 16;

define constant $crypto-shorthash-PRIMITIVE = "siphash24";

define inline C-function crypto-shorthash-siphash24-bytes
  result res :: <C-size-t>;
  c-name: "crypto_shorthash_siphash24_bytes";
end;

define inline C-function crypto-shorthash-siphash24-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_shorthash_siphash24_keybytes";
end;

define inline C-function crypto-shorthash-siphash24
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_shorthash_siphash24";
end;

define constant $crypto-shorthash-siphash24-BYTES = 8;

define constant $crypto-shorthash-siphash24-KEYBYTES = 16;

define inline C-function crypto-sign-bytes
  result res :: <C-size-t>;
  c-name: "crypto_sign_bytes";
end;

define inline C-function crypto-sign-seedbytes
  result res :: <C-size-t>;
  c-name: "crypto_sign_seedbytes";
end;

define inline C-function crypto-sign-publickeybytes
  result res :: <C-size-t>;
  c-name: "crypto_sign_publickeybytes";
end;

define inline C-function crypto-sign-secretkeybytes
  result res :: <C-size-t>;
  c-name: "crypto_sign_secretkeybytes";
end;

define inline C-function crypto-sign-primitive
  result res :: <C-string>;
  c-name: "crypto_sign_primitive";
end;

define inline C-function crypto-sign-seed-keypair
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  input parameter seed_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_seed_keypair";
end;

define inline C-function crypto-sign-keypair
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_keypair";
end;

define inline C-function %crypto-sign
  input parameter sm_ :: <C-buffer-offset>;
  input parameter smlen-p_ :: <unsigned-long-long*>;
  input parameter m_ :: <C-buffer-offset>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign";
end;

define inline C-function %crypto-sign-open
  input parameter m_ :: <C-buffer-offset>;
  input parameter mlen-p_ :: <unsigned-long-long*>;
  input parameter sm_ :: <C-buffer-offset>;
  input parameter smlen_ :: <C-unsigned-long>;
  input parameter pk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_open";
end;

define inline C-function %crypto-sign-detached
  input parameter sig_ :: <C-buffer-offset>;
  input parameter siglen-p_ :: <unsigned-long-long*>;
  input parameter m_ :: <C-buffer-offset>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_detached";
end;

define inline C-function %crypto-sign-verify-detached
  input parameter sig_ :: <C-buffer-offset>;
  input parameter m_ :: <C-buffer-offset>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter pk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_verify_detached";
end;

define constant $crypto-sign-BYTES = 64;

define constant $crypto-sign-SEEDBYTES = 32;

define constant $crypto-sign-PUBLICKEYBYTES = 32;

define constant $crypto-sign-SECRETKEYBYTES = 64;

define constant $crypto-sign-PRIMITIVE = "ed25519";

define inline C-function crypto-sign-ed25519-bytes
  result res :: <C-size-t>;
  c-name: "crypto_sign_ed25519_bytes";
end;

define inline C-function crypto-sign-ed25519-seedbytes
  result res :: <C-size-t>;
  c-name: "crypto_sign_ed25519_seedbytes";
end;

define inline C-function crypto-sign-ed25519-publickeybytes
  result res :: <C-size-t>;
  c-name: "crypto_sign_ed25519_publickeybytes";
end;

define inline C-function crypto-sign-ed25519-secretkeybytes
  result res :: <C-size-t>;
  c-name: "crypto_sign_ed25519_secretkeybytes";
end;

define inline C-function %crypto-sign-ed25519
  input parameter sm_ :: <C-buffer-offset>;
  input parameter smlen-p_ :: <unsigned-long-long*>;
  input parameter m_ :: <C-buffer-offset>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519";
end;

define inline C-function %crypto-sign-ed25519-open
  input parameter m_ :: <C-buffer-offset>;
  input parameter mlen-p_ :: <unsigned-long-long*>;
  input parameter sm_ :: <C-buffer-offset>;
  input parameter smlen_ :: <C-unsigned-long>;
  input parameter pk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519_open";
end;

define inline C-function %crypto-sign-ed25519-detached
  input parameter sig_ :: <C-buffer-offset>;
  input parameter siglen-p_ :: <unsigned-long-long*>;
  input parameter m_ :: <C-buffer-offset>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519_detached";
end;

define inline C-function %crypto-sign-ed25519-verify-detached
  input parameter sig_ :: <C-buffer-offset>;
  input parameter m_ :: <C-buffer-offset>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter pk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519_verify_detached";
end;

define inline C-function crypto-sign-ed25519-keypair
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519_keypair";
end;

define inline C-function crypto-sign-ed25519-seed-keypair
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  input parameter seed_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519_seed_keypair";
end;

define inline C-function crypto-sign-ed25519-pk-to-curve25519
  input parameter curve25519-pk_ :: <unsigned-char*>;
  input parameter ed25519-pk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519_pk_to_curve25519";
end;

define inline C-function crypto-sign-ed25519-sk-to-curve25519
  input parameter curve25519-sk_ :: <unsigned-char*>;
  input parameter ed25519-sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519_sk_to_curve25519";
end;

define inline C-function crypto-sign-ed25519-sk-to-seed
  input parameter seed_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519_sk_to_seed";
end;

define inline C-function crypto-sign-ed25519-sk-to-pk
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_ed25519_sk_to_pk";
end;

define constant $crypto-sign-ed25519-BYTES = 64;

define constant $crypto-sign-ed25519-SEEDBYTES = 32;

define constant $crypto-sign-ed25519-PUBLICKEYBYTES = 32;

define constant $crypto-sign-ed25519-SECRETKEYBYTES = 64;

define inline C-function crypto-sign-edwards25519sha512batch
  input parameter sm_ :: <unsigned-char*>;
  input parameter smlen-p_ :: <unsigned-long-long*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_edwards25519sha512batch";
end;

define inline C-function crypto-sign-edwards25519sha512batch-open
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen-p_ :: <unsigned-long-long*>;
  input parameter sm_ :: <unsigned-char*>;
  input parameter smlen_ :: <C-unsigned-long>;
  input parameter pk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_edwards25519sha512batch_open";
end;

define inline C-function crypto-sign-edwards25519sha512batch-keypair
  input parameter pk_ :: <unsigned-char*>;
  input parameter sk_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_sign_edwards25519sha512batch_keypair";
end;

define constant $crypto-sign-edwards25519sha512batch-BYTES = 64;

define constant $crypto-sign-edwards25519sha512batch-PUBLICKEYBYTES = 32;

define constant $crypto-sign-edwards25519sha512batch-SECRETKEYBYTES = 64;

define inline C-function crypto-stream-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_keybytes";
end;

define inline C-function crypto-stream-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_noncebytes";
end;

define inline C-function crypto-stream-primitive
  result res :: <C-string>;
  c-name: "crypto_stream_primitive";
end;

define inline C-function crypto-stream
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream";
end;

define inline C-function crypto-stream-xor
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_xor";
end;

define constant $crypto-stream-KEYBYTES = 32;

define constant $crypto-stream-NONCEBYTES = 24;

define constant $crypto-stream-PRIMITIVE = "xsalsa20";

define inline C-function crypto-stream-aes128ctr-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_aes128ctr_keybytes";
end;

define inline C-function crypto-stream-aes128ctr-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_aes128ctr_noncebytes";
end;

define inline C-function crypto-stream-aes128ctr-beforenmbytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_aes128ctr_beforenmbytes";
end;

define inline C-function crypto-stream-aes128ctr
  input parameter out_ :: <unsigned-char*>;
  input parameter outlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_aes128ctr";
end;

define inline C-function crypto-stream-aes128ctr-xor
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter inlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_aes128ctr_xor";
end;

define inline C-function crypto-stream-aes128ctr-beforenm
  input parameter c_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_aes128ctr_beforenm";
end;

define inline C-function crypto-stream-aes128ctr-afternm
  input parameter out_ :: <unsigned-char*>;
  input parameter len_ :: <C-unsigned-long>;
  input parameter nonce_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_aes128ctr_afternm";
end;

define inline C-function crypto-stream-aes128ctr-xor-afternm
  input parameter out_ :: <unsigned-char*>;
  input parameter in_ :: <unsigned-char*>;
  input parameter len_ :: <C-unsigned-long>;
  input parameter nonce_ :: <unsigned-char*>;
  input parameter c_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_aes128ctr_xor_afternm";
end;

define constant $crypto-stream-aes128ctr-KEYBYTES = 16;

define constant $crypto-stream-aes128ctr-NONCEBYTES = 16;

define constant $crypto-stream-aes128ctr-BEFORENMBYTES = 1408;

define inline C-function crypto-stream-chacha20-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_chacha20_keybytes";
end;

define inline C-function crypto-stream-chacha20-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_chacha20_noncebytes";
end;

define inline C-function crypto-stream-chacha20
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_chacha20";
end;

define inline C-function crypto-stream-chacha20-xor
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_chacha20_xor";
end;

define inline C-function crypto-stream-chacha20-xor-ic
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter ic_ :: <uint64-t>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_chacha20_xor_ic";
end;

define inline C-function crypto-stream-chacha20-ietf-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_chacha20_ietf_noncebytes";
end;

define inline C-function crypto-stream-chacha20-ietf
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_chacha20_ietf";
end;

define inline C-function crypto-stream-chacha20-ietf-xor
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_chacha20_ietf_xor";
end;

define inline C-function crypto-stream-chacha20-ietf-xor-ic
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter ic_ :: <uint32-t>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_chacha20_ietf_xor_ic";
end;

define constant $crypto-stream-chacha20-KEYBYTES = 32;

define constant $crypto-stream-chacha20-NONCEBYTES = 8;

define constant $crypto-stream-chacha20-IETF-NONCEBYTES = 12;

define inline C-function crypto-stream-salsa20-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_salsa20_keybytes";
end;

define inline C-function crypto-stream-salsa20-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_salsa20_noncebytes";
end;

define inline C-function crypto-stream-salsa20
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_salsa20";
end;

define inline C-function crypto-stream-salsa20-xor
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_salsa20_xor";
end;

define inline C-function crypto-stream-salsa20-xor-ic
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter ic_ :: <uint64-t>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_salsa20_xor_ic";
end;

define constant $crypto-stream-salsa20-KEYBYTES = 32;

define constant $crypto-stream-salsa20-NONCEBYTES = 8;

define inline C-function crypto-stream-salsa2012-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_salsa2012_keybytes";
end;

define inline C-function crypto-stream-salsa2012-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_salsa2012_noncebytes";
end;

define inline C-function crypto-stream-salsa2012
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_salsa2012";
end;

define inline C-function crypto-stream-salsa2012-xor
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_salsa2012_xor";
end;

define constant $crypto-stream-salsa2012-KEYBYTES = 32;

define constant $crypto-stream-salsa2012-NONCEBYTES = 8;

define inline C-function crypto-stream-salsa208-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_salsa208_keybytes";
end;

define inline C-function crypto-stream-salsa208-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_salsa208_noncebytes";
end;

define inline C-function crypto-stream-salsa208
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_salsa208";
end;

define inline C-function crypto-stream-salsa208-xor
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_salsa208_xor";
end;

define constant $crypto-stream-salsa208-KEYBYTES = 32;

define constant $crypto-stream-salsa208-NONCEBYTES = 8;

define inline C-function crypto-stream-xsalsa20-keybytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_xsalsa20_keybytes";
end;

define inline C-function crypto-stream-xsalsa20-noncebytes
  result res :: <C-size-t>;
  c-name: "crypto_stream_xsalsa20_noncebytes";
end;

define inline C-function crypto-stream-xsalsa20
  input parameter c_ :: <unsigned-char*>;
  input parameter clen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_xsalsa20";
end;

define inline C-function crypto-stream-xsalsa20-xor
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_xsalsa20_xor";
end;

define inline C-function crypto-stream-xsalsa20-xor-ic
  input parameter c_ :: <unsigned-char*>;
  input parameter m_ :: <unsigned-char*>;
  input parameter mlen_ :: <C-unsigned-long>;
  input parameter n_ :: <unsigned-char*>;
  input parameter ic_ :: <uint64-t>;
  input parameter k_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_stream_xsalsa20_xor_ic";
end;

define constant $crypto-stream-xsalsa20-KEYBYTES = 32;

define constant $crypto-stream-xsalsa20-NONCEBYTES = 24;

define inline C-function crypto-verify-16-bytes
  result res :: <C-size-t>;
  c-name: "crypto_verify_16_bytes";
end;

define inline C-function crypto-verify-16
  input parameter x_ :: <unsigned-char*>;
  input parameter y_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_verify_16";
end;

define constant $crypto-verify-16-BYTES = 16;

define inline C-function crypto-verify-32-bytes
  result res :: <C-size-t>;
  c-name: "crypto_verify_32_bytes";
end;

define inline C-function crypto-verify-32
  input parameter x_ :: <unsigned-char*>;
  input parameter y_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_verify_32";
end;

define constant $crypto-verify-32-BYTES = 32;

define inline C-function crypto-verify-64-bytes
  result res :: <C-size-t>;
  c-name: "crypto_verify_64_bytes";
end;

define inline C-function crypto-verify-64
  input parameter x_ :: <unsigned-char*>;
  input parameter y_ :: <unsigned-char*>;
  result res :: <C-signed-int>;
  c-name: "crypto_verify_64";
end;

define constant $crypto-verify-64-BYTES = 64;

define constant <implementation-name> = <C-function-pointer>;
define constant <random> = <C-function-pointer>;
define constant <stir> = <C-function-pointer>;
define constant <uniform> = <C-function-pointer>;
define constant <buf> = <C-function-pointer>;
define constant <close> = <C-function-pointer>;
define C-struct <randombytes-implementation>
  sealed slot randombytes-implementation$implementation-name :: <implementation-name>;
  sealed slot randombytes-implementation$random :: <random>;
  sealed slot randombytes-implementation$stir :: <stir>;
  sealed slot randombytes-implementation$uniform :: <uniform>;
  sealed slot randombytes-implementation$buf :: <buf>;
  sealed slot randombytes-implementation$close :: <close>;
end;

define inline C-function randombytes-buf
  input parameter buf_ :: <C-void*>;
  input parameter size_ :: <C-size-t>;
  c-name: "randombytes_buf";
end;

define inline C-function randombytes-random
  result res :: <uint32-t>;
  c-name: "randombytes_random";
end;

define inline C-function randombytes-uniform
  input parameter upper-bound_ :: <uint32-t>;
  result res :: <uint32-t>;
  c-name: "randombytes_uniform";
end;

define inline C-function randombytes-stir
  c-name: "randombytes_stir";
end;

define inline C-function randombytes-close
  result res :: <C-signed-int>;
  c-name: "randombytes_close";
end;

define C-pointer-type <randombytes-implementation*> => <randombytes-implementation>;
define inline C-function randombytes-set-implementation
  input parameter impl_ :: <randombytes-implementation*>;
  result res :: <C-signed-int>;
  c-name: "randombytes_set_implementation";
end;

define inline C-function randombytes-implementation-name
  result res :: <C-string>;
  c-name: "randombytes_implementation_name";
end;

define inline C-function randombytes
  input parameter buf_ :: <unsigned-char*>;
  input parameter buf-len_ :: <C-unsigned-long>;
  c-name: "randombytes";
end;

define inline C-function sodium-runtime-has-neon
  result res :: <C-signed-int>;
  c-name: "sodium_runtime_has_neon";
end;

define inline C-function sodium-runtime-has-sse2
  result res :: <C-signed-int>;
  c-name: "sodium_runtime_has_sse2";
end;

define inline C-function sodium-runtime-has-sse3
  result res :: <C-signed-int>;
  c-name: "sodium_runtime_has_sse3";
end;

define inline C-function sodium-runtime-has-ssse3
  result res :: <C-signed-int>;
  c-name: "sodium_runtime_has_ssse3";
end;

define inline C-function sodium-runtime-has-sse41
  result res :: <C-signed-int>;
  c-name: "sodium_runtime_has_sse41";
end;

define inline C-function sodium-runtime-has-avx
  result res :: <C-signed-int>;
  c-name: "sodium_runtime_has_avx";
end;

define inline C-function sodium-runtime-has-pclmul
  result res :: <C-signed-int>;
  c-name: "sodium_runtime_has_pclmul";
end;

define inline C-function sodium-runtime-has-aesni
  result res :: <C-signed-int>;
  c-name: "sodium_runtime_has_aesni";
end;

define inline C-function sodium-memzero
  input parameter pnt_ :: <C-void*>;
  input parameter len_ :: <C-size-t>;
  c-name: "sodium_memzero";
end;

define inline C-function sodium-memcmp
  input parameter b1-_ :: <C-void*>;
  input parameter b2-_ :: <C-void*>;
  input parameter len_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "sodium_memcmp";
end;

define inline C-function sodium-compare
  input parameter b1-_ :: <unsigned-char*>;
  input parameter b2-_ :: <unsigned-char*>;
  input parameter len_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "sodium_compare";
end;

define inline C-function sodium-is-zero
  input parameter n_ :: <unsigned-char*>;
  input parameter nlen_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "sodium_is_zero";
end;

define inline C-function sodium-increment
  input parameter n_ :: <unsigned-char*>;
  input parameter nlen_ :: <C-size-t>;
  c-name: "sodium_increment";
end;

define inline C-function sodium-add
  input parameter a_ :: <unsigned-char*>;
  input parameter b_ :: <unsigned-char*>;
  input parameter len_ :: <C-size-t>;
  c-name: "sodium_add";
end;

define inline C-function sodium-bin2hex
  input parameter hex_ :: <C-string>;
  input parameter hex-maxlen_ :: <C-size-t>;
  input parameter bin_ :: <unsigned-char*>;
  input parameter bin-len_ :: <C-size-t>;
  result res :: <C-string>;
  c-name: "sodium_bin2hex";
end;

define C-pointer-type <size-t*> => <C-size-t>;
define C-pointer-type <statically-typed-pointer*> => <C-string>;
define inline C-function sodium-hex2bin
  input parameter bin_ :: <unsigned-char*>;
  input parameter bin-maxlen_ :: <C-size-t>;
  input parameter hex_ :: <C-string>;
  input parameter hex-len_ :: <C-size-t>;
  input parameter ignore_ :: <C-string>;
  input parameter bin-len_ :: <size-t*>;
  input parameter hex-end_ :: <statically-typed-pointer*>;
  result res :: <C-signed-int>;
  c-name: "sodium_hex2bin";
end;

define inline C-function sodium-mlock
  input parameter addr_ :: <C-void*>;
  input parameter len_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "sodium_mlock";
end;

define inline C-function sodium-munlock
  input parameter addr_ :: <C-void*>;
  input parameter len_ :: <C-size-t>;
  result res :: <C-signed-int>;
  c-name: "sodium_munlock";
end;

define inline C-function sodium-malloc
  input parameter size_ :: <C-size-t>;
  result res :: <C-void*>;
  c-name: "sodium_malloc";
end;

define inline C-function sodium-allocarray
  input parameter count_ :: <C-size-t>;
  input parameter size_ :: <C-size-t>;
  result res :: <C-void*>;
  c-name: "sodium_allocarray";
end;

define inline C-function sodium-free
  input parameter ptr_ :: <C-void*>;
  c-name: "sodium_free";
end;

define inline C-function sodium-mprotect-noaccess
  input parameter ptr_ :: <C-void*>;
  result res :: <C-signed-int>;
  c-name: "sodium_mprotect_noaccess";
end;

define inline C-function sodium-mprotect-readonly
  input parameter ptr_ :: <C-void*>;
  result res :: <C-signed-int>;
  c-name: "sodium_mprotect_readonly";
end;

define inline C-function sodium-mprotect-readwrite
  input parameter ptr_ :: <C-void*>;
  result res :: <C-signed-int>;
  c-name: "sodium_mprotect_readwrite";
end;

define inline C-function sodium-version-string
  result res :: <C-string>;
  c-name: "sodium_version_string";
end;

define inline C-function sodium-library-version-major
  result res :: <C-signed-int>;
  c-name: "sodium_library_version_major";
end;

define inline C-function sodium-library-version-minor
  result res :: <C-signed-int>;
  c-name: "sodium_library_version_minor";
end;

define constant $SODIUM-VERSION-STRING = "1.0.8";

define constant $SODIUM-LIBRARY-VERSION-MAJOR = 9;

define constant $SODIUM-LIBRARY-VERSION-MINOR = 1;

