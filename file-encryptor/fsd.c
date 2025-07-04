/* fsd.c */
#include "file.h"
#define F fflush(stdout)

int8 *readkey(const char *prompt){    
    // we want to make sure to basically record the keystrokes to get our key
    // no displaying the characters though which is done in changeecho
    
    char buf[2056];
    int8 *p;
    int16 size;

    printf("%s ", prompt);
    fflush(stdout);

    changeecho(false);
    memset(buf, 0, 2056);
    fgets((char *)buf, 2055, stdin);
    changeecho(true);

    //gets the length of the string in buffer
    //if the length is greater than 2048, it only will consider the first 2048
    size = min((int16)strlen((char *)buf),2048);
    p = buf + size - 1;

    //removing new line characters like \n from the end of the key
    while (size && ((*p == 10) || (*p == 13))) {
        *p-- = 0;
        size--;
    }

    if (!size)
        return 0;
    
    p = (int8 *)malloc(size);
    memset(p, 0, size);

    //basically here we wanna copy however many bytes size is from buf to p
    //but because strncpy is annoying about the possibility of having a longer source than destination
    //we need to do all this stuff to ignore the warnings
    #pragma GCC diagnostic push
        strncpy((char *)p, (char *)buf, size);
    #pragma GCC diagnostic pop

    return p;
}

void changeecho(bool enabled) {
    //this function will allow us to change between echoing keystrokes
    struct termios *t;
    t = (struct termios *)malloc(sizeof(struct termios));
    
    tcgetattr(0,t);
    
    if (enabled) {
        t->c_lflag |= ECHO;
    }else {
        t->c_lflag &= ~ECHO;
    }
    
    tcsetattr(0, TCSANOW, t);
    free(t);
    return;

}

void wipe(int8 *buf, int16 size){
    //we need this method to we can properly erase sensitive data
    //from what im seeing online and stuff they say u should do multiple passes
    //make it unpredictable or something, I don't know if more than 1 is necessary
    //but we listen
    int16 n, i;
    int8 *p;
    n=20;
    //so basically 20 passes on each pass we go through each byte in buffer make it 0
    while (n--)
        for (i = size, p = buf; i; i--)
            *p++ = 0;

    return;
}

int16 getoffset(Arcfour *rc4, int outfd) { 
    int16 offset;
    int8 offenc[2];
    int8 offdec[2];
    int16 n;

    //read first 2 bytes
    n = read(outfd, offenc, 2);

    if(n!=2){
        perror("error reading offset");
        return -1;
    }

    offdec[0] = offenc[0] ^ rc4byte(rc4);
    offdec[1] = offenc[1] ^ rc4byte(rc4);

    offset = ((int16)offdec[0] << 8) | (int16)offdec[1];

    return offset;
}

void parsepadding(Arcfour *rc4, int outfd, int16 offset) {
    int16 n;
    int8 *tempbuf;

    tempbuf = malloc(1);
    if (!tempbuf) {
        perror("malloc");
        exit(1);
    }

    while(offset--){
        n = read(outfd,tempbuf,1);
        if (n != 1) {
            perror("padding read error");
            free(tempbuf);
            exit(1);
        }
        rc4byte(rc4);
    }
    free(tempbuf);
}

int8 *sha256(int8* data,int16 size){
    SHA256_CTX *ctx;
    int8 *buf;

    ctx = malloc(sizeof(SHA256_CTX));
    //256 bits so we allocate 32 bytes
    buf = malloc(32);
    assert(ctx && buf);

    memset(buf,0,32);
    SHA256_Init(ctx);
    SHA256_Update(ctx, data, size);
    SHA256_Final(buf, ctx);
    free(ctx);

    return buf;
}

bool verify(Arcfour *rc4, int outfd,int8 *key, int16 size){
    int16 offset;
    int8 *hashedkeyfile;
    int8 *userkeyhash;
    int n;

    //get the offset from the first 2 bytes
    offset = getoffset(rc4, outfd);
    if (offset<=0) {
        fprintf(stderr, "Failed to get offset or invalid key\n");
        return false;
    }

    //decrypt padding just to match cipher internal state
    parsepadding(rc4,outfd,offset);

    //get key hash from next 32 bytes and compare with hash
    hashedkeyfile = malloc(32);
    if(!hashedkeyfile){
        perror("malloc issue");
        exit(1);
    }
    //reading the hashed key
    n = read(outfd, hashedkeyfile, 32);
    if(n!= 32){
        perror("didnt read full key hash");
        free(hashedkeyfile);
        exit(1);
    }
    //decrypting the hashed key
    for (int i = 0; i < 32; i++) {
        hashedkeyfile[i] = hashedkeyfile[i] ^ rc4byte(rc4);
    }

    userkeyhash = sha256(key,size);
    if (!userkeyhash) {
        perror("sha256 failed");
        free(hashedkeyfile);
        return false;
    }

    bool valid = (memcmp(userkeyhash, hashedkeyfile, 32) == 0);

    free(userkeyhash);
    free(hashedkeyfile);
    return valid;

}

void encrypting(Arcfour *rc4, int outfd, int decfd) {
    int8 *outbyte, *decbyte;
    ssize_t n;
    
    outbyte = malloc(1);
    decbyte = malloc(1);

    while ((n = read(outfd, outbyte, 1)) == 1) {
        *decbyte = *outbyte ^ rc4byte(rc4);
        if (write(decfd, decbyte, 1) != 1) {
            perror("write");
            exit(1);
        }
    }

    if (n < 0) {
        perror("read");
        exit(1);
    }
    
    free(outbyte);
    free(decbyte);
}


int main(int argc, char *argv[]){
    Arcfour *rc4;
    char *outfile, *decryptedfile;
    int outfd, decfd;
    int8 *key;
    int16 size;
    bool valid;
    
    if(argc < 3) { 
        fprintf(stderr,"Usage: %s <outfile> <decryptedfile> \n", *argv);
        return -1;
    }

    outfile = argv[1];
    decryptedfile = argv[2];
    key = readkey("Key:");
    //if no key
    if (!key) {
        fprintf(stderr, "Abort due to invalid/no key");
        return -1;
    }
    
    //initialize our encryption/decryption cipher!
    printf("\nInitializing decryption..."); F;
    size = (int16)strlen((char *)key);
    rc4 = rc4init(key,size);

    if (!rc4) {
        printf("Initialization of encryption library failed\n");
        perror("rc4init");
        wipe(key,size);
        free(key);
        return -1;
    }else {
        printf("Initialization done!\n");
    }

    //opening outfile(returns a file descriptor so a non-negative interger if good)
    outfd = open(outfile, O_RDONLY);

    if (outfd < 1) {
        perror("opening outfile");
        rc4uninit(rc4);
        wipe(key,size);
        free(key);
        return-1;
    }
    
    //opening decryptedfile
    decfd = open(decryptedfile, O_WRONLY | O_CREAT, 00600);

    if (decfd < 1) {
        perror("opening decryptedfile");
        close(outfd);
        rc4uninit(rc4);
        wipe(key,size);
        free(key);
        return-1;
    }

    valid = verify(rc4, outfd, key, size);

    if(!valid){
        printf("Key not valid. %s","Try again!");
        close(outfd);
        close(decfd);
        rc4uninit(rc4);
        wipe(key,size);
        free(key);
        return -1;
    }

    //since rc4 is nicely symmetric, we can just re-encrypt to decrypt
    printf("Beginning decryption: %s -> %s\n", outfile, decryptedfile);
    encrypting(rc4,outfd,decfd);
    
    close(outfd);
    close(decfd);
    rc4uninit(rc4);
    wipe(key,size);
    free(key);

    return 0;
}