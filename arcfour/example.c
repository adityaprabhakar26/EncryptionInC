/* example.c */
#include "arcfour.h"

#define F fflush(stdout)


int main(void);

/* es31 cm63 <- output should look like something along these lines
1 byte is represented by 2 hexadecimals, and then 2 bytes per group
separated by spaces. this function will be our binary printer */

void printbin(int8 *input, const int16 size) {
    int16 i;
    int8 *p;

    //assert checks if predicate is true, else holds program
    assert(size > 0);

    for (i=size, p=input; i; i--,p++) {
        //basically if i+1 is even space
        if (!(i % 2))
            printf(" ");
        printf("%.02x", *p);
    }

    printf("\n");

    return;

}


int main() {

    Arcfour *rc4;

    /* size key and size text */
    int16 skey, stext;
    char *key, *from;
    int8 *encrypted, *decrypted;

    /* replace with key of 8 bits to 2048 bits */
    key = "tomatoes"; 
    skey = strlen(key);

    /* what we are encrypting */
    from =  "Shall I compare thee to a summer's day?"; 
    stext = strlen(from);

    //encrypt
    printf("initializing encryption..."); F;
    rc4 = rc4init((int8 *)key,skey);
    printf("done\n");

    printf("'%s'\n ->",from);
    encrypted = rc4encrypt(rc4,(int8 *)from, stext);
    printbin(encrypted,stext);
    

    //decrypt
    rc4uninit(rc4);

    printf("\ninitializing decryption..."); F;
    rc4 = rc4init((int8 *)key,skey);
    printf("done\n");
    

    decrypted = rc4decrypt(rc4, encrypted, stext);
    printf("->'%s'\n",decrypted);

    rc4uninit(rc4);
    
    return 0;

}