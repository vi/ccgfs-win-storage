ccgfs-storage.exe: *.c *.h
		i586-mingw32msvc-gcc packet.c xl.c xl_errno.c storage.c -o ccgfs-storage.exe
