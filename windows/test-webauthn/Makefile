# Note: run VsDevCmd.bat to set up env vars

test-webauthn.exe: test-webauthn.c
	cl /Z7 test-webauthn.c /link webauthn.lib User32.lib

clean:
	rm test-webauthn.exe *.pdb *.obj *.ilk
