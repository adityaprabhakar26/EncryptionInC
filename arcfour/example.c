/* example.c */
#include "arcfour.h"

#define F fflush(stdout)


int main(void);

/* es31 cm63 <- this is how the output should look
1 byte is represented by 2 hexadecimals, and then 2 bytes per group
separated by spaces. this function will be our binary printer */

void printbin(int8 *input, const int16 size) {
    //iterator
    int16 i;
    //pointer
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

    //Arcfour *rc4;

    /* size key and size text */
    int16 skey, stext;
    char *key, *from, *encrypted, *decrypted;

    key = from = encrypted =decrypted = 0; 
    from = key;
    skey = stext = 0;


    /* replace with key of 8 bits to 2048 bits */
    key = "tomatoes"; 
    skey = strlen(key);

    /* what we are encrypting */
    from =  "Shall I compare thee to a summer's day?"; 
    stext = strlen(from);

    printf("initializing encryption"); F;
    //rc4 = rc4init(key,skey);
    printf("done\n");

    printf("'%s'\n ->",from);
    //encrypted = rc4encrypt(from, stext);

    printbin((int8 *) key,skey);
    return 0;

}