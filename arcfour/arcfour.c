/* arcfour.c */
#include "arcfour.h"


//initializing, so key scheduling 
export Arcfour *rc4init(int8 *key, int16 size) { 
    
    int16 x;
    int8 temp1, temp2;
    Arcfour *p;
    int32 n;

    // make sure we can allocate memory for the structure
    if (!(p = malloc(sizeof(struct s_arcfour)))){
        perror("malloc failed");
        exit(1);
    }

    // zero our S array by using the pointer to the struct's array S
    // and then zero out other values of struct
    for (x = 0; x<256; x++){
        p->S[x] = 0;
    }
    p->i = p->j = p->k = 0;
    temp1 = temp2 = 0;

    //fill S array
    for (p->i = 0; p->i < 256; p->i++){
        p->S[p->i] = p-> i;
    }

    //look at the read me
    //the Key Scheduling section explains it with pseudocode
    for (p->i = 0; p->i < 256; p->i++){
        
        temp1 = p->i % size;
        
        //setting j, broken into the calc and then mod
        temp2 = p->j + p->S[p->i] + key[temp1];
        p->j = temp2 % 256;
        
        //here is just the swap
        temp1 = p->S[p->i];
        temp2 = p->S[p->j];
        p->S[p->i] = temp2;
        p->S[p->j] = temp1;

    }
    
    //re initialize so we can call stream generation right after
    p->i = p->j = 0;

    rc4whitewash(n,p);

    return p;
}

//creates a byte of the keystream(pseudo random algo / stream gen)
int8 rc4byte(Arcfour *p) { 
    int16 temp1, temp2;
    
    p->i = (p->i + 1) % 256;
    p->j = (p->j + p->S[p->i ]) % 256;

    //swap
    temp1 = p->S[p->i];
    temp2 = p->S[p->j];
    p->S[p->i] = temp2;
    p->S[p->j] = temp1;

    temp1 = (p->S[p->i] + p->S[p->j]) % 256;

    //one keystream element gets set
    //function gets called to produce every element of the keystream
    p->k = p->S[temp1];

    return p->k;
}

//encryption
export int8 *rc4encrypt(Arcfour *p, int8 *plaintext, int16 size){
    int8 *ciphertext;
    int16 x;

    ciphertext = (int8 *)malloc(size + 1);
    if (!ciphertext){
        perror("malloc failed");
        exit(1);
    }

    //here is the actual encryption, ^ is XOR
    for(x=0; x<size; x++){
        ciphertext[x] = plaintext[x] ^ rc4byte(p);
    }
    
    return ciphertext;
}