Module: dylan-user

define module sodium
  use common-dylan;
  use c-ffi;
  use libsodium,
    rename: {
      crypto-sign => %crypto-sign,
      crypto-sign-keypair => %crypto-sign-keypair,
      crypto-sign-open => %crypto-sign-open,
      crypto-sign-ed25519 => %crypto-sign-ed25519,
      crypto-sign-ed25519-keypair => %crypto-sign-ed25519-keypair,
      crypto-sign-ed25519-open => %crypto-sign-ed25519-open,
      crypto-sign-detached => %crypto-sign-detached,
      crypto-sign-verify-detached => %crypto-sign-verify-detached,
      crypto-sign-ed25519-detached => %crypto-sign-ed25519-detached,
      crypto-sign-ed25519-sk-to-pk => %crypto-sign-ed25519-sk-to-pk,
      crypto-sign-ed25519-verify-detached => %crypto-sign-ed25519-verify-detached,
    };

  export <sodium-error>,
         sodium-error-operation;

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
