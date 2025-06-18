OPENSSL = /opt/homebrew/opt/openssl@3

all: fse

fse: fse.o ../arcfour/arcfour.o
	gcc -o fse fse.o ../arcfour/arcfour.o -I$(OPENSSL)/include -L$(OPENSSL)/lib -lssl -lcrypto -O2 -Wall

fse.o: fse.c file.h
	gcc -c -I$(OPENSSL)/include -O2 -Wall fse.c

clean:
	rm -f fse.o fse
