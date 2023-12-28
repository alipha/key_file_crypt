CC           = gcc
LD           = gcc
CFLAGS       = -Wall -O3 -c
LDFLAGS      = -Wall -O3

default: crypt

.SILENT:

crypt.o : crypt.c aes.h aes.o
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o  $@ $<

aes.o : aes.c aes.h
	echo [CC] $@ $(CFLAGS)
	$(CC) $(CFLAGS) -o $@ $<

crypt : aes.o crypt.o
	echo [LD] $@
	$(LD) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o crypt
