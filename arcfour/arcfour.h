/* arcfour.h */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#define _GNU_SOURCE


#define MS                  500
#define export              __attribute__((visibility("default")))

//this relies on the fact that encrypting encrypted text decrypts it
#define rc4decrypt(x,y,z)     rc4encrypt(x,y,z)

#define rc4uninit(x)        free(x)

//this is what makes rc4 a little more secure for our purposes 
//we will create a bunch of bytes of the keystream and just ignore it
//volatile int8 type cast is just so gcc doesnt optimzie it away
#define rc4whitewash(x,y)     for (x=0; x<(MS*1000000); x++) \
                                (volatile int8) rc4byte(y);


/* some types we will use a lot to make things easy */
typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned int int32;

struct s_arcfour { 
    int16 i, j, k;
    int8 S[256];
};
typedef struct s_arcfour Arcfour;

//init function + key scheduling
export Arcfour *rc4init(int8*, int16);

//byte by byte keystream generator
int8 rc4byte(Arcfour*);

//encryption
export int8 *rc4encrypt(Arcfour*, int8*, int16);
