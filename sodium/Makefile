MELANGE=melange

libsodium.dylan: libsodium.intr
	$(MELANGE) -Tc-ffi \
             -m libsodium-module.dylan \
             libsodium.intr \
             libsodium.dylan

