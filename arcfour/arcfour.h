/* arcfour.h */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

//this relies on the fact that encrypting encrypted text decrypts it
#define rc4decrypt(x,y)     rc4encrypt(x,y)

struct s_arcfour { 
    
};
typedef struct s_arcfour Arcfour;


/* some types we will use a lot to make things easy */
typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned int int32;

//init function
Arcfour *rc4init(int8*, int16);
int8 rc4byte(void);
int8 *rc4encrypt(int8*, int16);
