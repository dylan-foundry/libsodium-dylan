module: sodium
synopsis: Error handling helpers.
author: Bruce Mitchener, Jr.
copyright: See LICENSE file in this distribution.

define class <sodium-error> (<error>)
  constant slot sodium-error-operation :: <string>,
    required-init-keyword: operation:;
end class;

define inline-only function check-error
    (res :: <integer>, operation :: <string>)
 => ()
  if (res ~= 0)
    error(make(<sodium-error>, operation: operation));
  end if;
end function;
