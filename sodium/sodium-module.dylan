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
    };

  export crypto-sign-keypair,
         crypto-sign-ed25519-keypair,
         public-signing-key-data,
         secret-signing-key-data;

  export crypto-sign,
         crypto-sign-open,
         <signed-payload>,
         signed-payload-data,
         signed-payload-size;
end module sodium;
