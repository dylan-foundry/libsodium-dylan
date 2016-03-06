module: sodium-test-suite
synopsis: Test suite for the sodium library.

define suite sodium-test-suite ()
  suite auth-test-suite;
  suite signatures-test-suite;
end suite;
