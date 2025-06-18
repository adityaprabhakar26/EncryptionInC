/* file.h */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/random.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <termios.h>
#include "../arcfour/arcfour.h"

#define encryptfile(x,y,z,a,b)  \
    addheader(x,y,a,b);         \
    decryptfile(x,y,z)
#define min(x,y)                (y<x)?y:x;
#define max(x,y)                (y>x)?y:x;
#define true 1
#define false 0

typedef unsigned int int32;
typedef unsigned short int int16;
typedef unsigned char int8;
typedef unsigned char bool;

bool echo(bool);
int8 *readline(const char*);
bool verify(Arcfour*,int,int8*,int16);
void wipe(int8*,int16);
int16 *rndsecure16(void);
int8 *rndsecure8x(int16);
int8 *sha256(int8*,int16);
void addheader(Arcfour*,int,int8*,int16);
void padding(Arcfour*,int,int16);
void keyhash(Arcfour*,int,int8*,int16);
void decryptfile(Arcfour*,int,int);