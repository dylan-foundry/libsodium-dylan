Module: dylan-user

define library sodium
  use common-dylan;
  use c-ffi;

  export sodium, libsodium;
end library sodium;
