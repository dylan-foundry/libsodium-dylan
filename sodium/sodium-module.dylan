Module: dylan-user

define module sodium
  use common-dylan;
  use c-ffi;
  use libsodium,
    rename: {
      crypto-sign-keypair => %crypto-sign-keypair,
      crypto-sign-ed25519-keypair => %crypto-sign-ed25519-keypair,
      crypto-sign-ed25519-sk-to-pk => %crypto-sign-ed25519-sk-to-pk,
    },
    export: {
      $crypto-auth-BYTES,
      $crypto-auth-KEYBYTES,
      $crypto-auth-PRIMITIVE,
      $crypto-auth-hmacsha256-BYTES,
      $crypto-auth-hmacsha256-KEYBYTES,
      $crypto-auth-hmacsha512-BYTES,
      $crypto-auth-hmacsha512-KEYBYTES,
      $crypto-auth-hmacsha512256-BYTES,
      $crypto-auth-hmacsha512256-KEYBYTES
    };

  export <sodium-error>,
         sodium-error-operation;

  export crypto-auth,
         crypto-auth-verify,
         crypto-auth-hmacsha256,
         crypto-auth-hmacsha256-verify,
         crypto-auth-hmacsha512,
         crypto-auth-hmacsha512-verify,
         crypto-auth-hmacsha512256,
         crypto-auth-hmacsha512256-verify;

  export crypto-sign-keypair,
         crypto-sign-ed25519-keypair,
         crypto-sign-ed25519-sk-to-pk,
         public-signing-key-data,
         secret-signing-key-data;

  export crypto-sign,
         crypto-sign-open,
         <signed-payload>,
         signed-payload-data,
         signed-payload-size;

  export crypto-sign-detached,
         crypto-sign-verify-detached,
         <detached-signature>,
         detached-signature-data,
         detached-signature-size;
end module sodium;
