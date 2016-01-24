module: dylan-user

define library sodium-test-suite
  use common-dylan;
  use c-ffi;
  use sodium;
  use testworks;
  use system;

  export sodium-test-suite;
end library;

define module sodium-test-suite
  use common-dylan;
  use c-ffi;
  use sodium;
  use testworks;

  export sodium-test-suite;
end module;
