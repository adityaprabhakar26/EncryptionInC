/* fse.c */
#include "file.h"
#define F fflush(stdout)


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

int16 *rndsecure16() {
    char *buf;
    int16 *p;
    int16 n;
    int fd;

    if(!(buf = malloc(2))) {
        perror("malloc");
        exit(-1);
    }else{
        //zeroing it out by going byte by byte w pointer
        *buf=*(buf+1)=0;
    }

    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        perror("open /dev/urandom");
        free(buf);
        return 0;
    }

    n = read(fd, buf, 2);
    p = (int16 *)buf;

    //make sure 2 bytes and nonzero
    assert(*p && (n==2));
    close(fd);
    return p;
}

int8 *securerand(int16 size) {
    //this function will generate random bytes securely
    //we basically allocate a buffer of our size, fill it in
    //ideally we can use linux getrandom entropy pool but we can't since macOS
    //so we use dev/urandom because supposedly its cryptographically secure and gives me random bytes
    
    int8 *buf, *p;
    int16 n,m;
    int fd;

    //incase malloc fails
    if(!(buf = (int8 *)malloc(size))){
        perror("malloc fail");
        exit(-1);
    }else {
        memset((char *)buf,0,size);
    }

    //open it
    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        perror("open /dev/urandom");
        free(buf);
        return 0;
    }
    
    n = read(fd, buf, size);
    p = buf;

    if (n < size) {
        fprintf(stderr, "Warning: Going to take a bit longer\n");

        if (n > 0) {
            p += n;
            size -= n;
        }

        m = read(fd, p, size);
        close(fd);

        if (m != size) {
            free(buf);
            fprintf(stderr, "Failed to read enough random bytes.\n");
            exit(-1);
        }
    } else {
        close(fd);
    }

    return buf;
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

void keyhash(Arcfour *rc4, int fd, int8 *key, int16 size) {
    int x;
    int16 n;
    int8 *p, *hash;
    int8 buf[2];
    int8 unencrypted, encrypted;
    //so p is a pointer walking thru the hash
    //and buf holds the encrypted byte before we write it
    
    //sha256 is 256 bits = 32 bytes
    n=32;
    *(buf+1)=0;
    hash = sha256(key,size);
    p = hash;

    //basically for every byte of hash, we use p to iterate over the bytes
    //so unencrypted is the byte of the hashed key
    //we then encrypt it with our rc4 custom cipher
    //store it in our buffer, then write it in
    while(n--) {
        unencrypted = *p++;
        encrypted = unencrypted ^ rc4byte(rc4);
        *buf = encrypted;
        x = write(fd, (char *)buf, 1);
        assert(x == 1);
    }

    free(hash);

    return;

}

void padding(Arcfour *rc4, int fd, int16 size) {
    int8 unencrypted, encrypted;
    int8 buf[2];
    int8 *pad, *p;
    int16 n;
    int x;

    //idea here is we use our offset value to create
    //that many encrypted bytes as a padding

    n = size;
    *(buf+1) =0;
    pad = securerand(size);

    p = pad;
    while(n--){
        unencrypted = *p++;
        encrypted = unencrypted ^ rc4byte(rc4);
        *buf = encrypted;

        x = write(fd, (char *)buf, 1);
        assert(x == 1);
    }
    
    free(pad);


    return;
}

void addheader(Arcfour *rc4,int fd, int8 *key,int16 size) {
    int16 *offset;
    int8 b[2], p[3];
    int n;

    //so offset is a 2 byte/16 bit number
    //its used to determine padding size
    //b has our 2 raw bytes of the offset
    //p has encrypted version of b

    //this just 0s out incase
    *b=*(b+1) = 0;
    *p=*(p+1)=*(p+2) = 0;

    //generate 2 byte offset and make sure its not 0
    offset = rndsecure16();
    assert(*offset > 0);

    //since we can only encrypt a byte at a time
    //we use b to split offset into our 2 bytes
    *b =     (*offset >> 8);
    *(b+1) = (*offset & 0x00FF);
    
    //then we encrypt them
    *p = rc4byte(rc4) ^ *b;
    *(p+1) = rc4byte(rc4) ^ *(b+1);
    *(p+2) = 0;

    n = write(fd, (char *)p, 2);
    assert(n == 2);

    //then we make our padding and hash the key!
    padding(rc4, fd, *offset);
    keyhash(rc4, fd, key, size);
    free(offset);

    return;
}

void encrypting(Arcfour *rc4, int infd, int outfd) {
    int8 *inbyte, *outbyte;
    ssize_t n;
    
    inbyte = malloc(1);
    outbyte = malloc(1);

    while ((n = read(infd, inbyte, 1)) == 1) {
        *outbyte = *inbyte ^ rc4byte(rc4);
        if (write(outfd, outbyte, 1) != 1) {
            perror("write");
            exit(1);
        }
    }

    if (n < 0) {
        perror("read");
        exit(1);
    }
    
    free(inbyte);
    free(outbyte);
}

int main(int argc, char *argv[]){
    Arcfour *rc4;
    char *infile, *outfile;
    int infd, outfd;
    int8 *key;
    int16 size;
    
    if(argc < 3) { 
        fprintf(stderr,"Usage: %s <infile> <outfile> \n", *argv);
        return -1;
    }

    infile = argv[1];
    outfile = argv[2];
    key = readkey("Key:");
    //if no key
    if (!key) {
        fprintf(stderr, "Abort due to invalid/no key");
        return -1;
    }

    //initialize our encryption cipher!
    printf("\nInitializing..."); F;
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

    //opening infile(returns a file descriptor so a non-negative interger if good)
    infd = open(infile, O_RDONLY);

    if (infd < 1) {
        perror("opening infile");
        rc4uninit(rc4);
        wipe(key,size);
        free(key);
        return-1;
    }
    
    //opening outfile
    outfd = open(outfile, O_WRONLY | O_CREAT, 00600);

    if (outfd < 1) {
        perror("opening outfile");
        close(infd);
        rc4uninit(rc4);
        wipe(key,size);
        free(key);
        return-1;
    }


    //encrypt it!
    printf("Beginning encryption: %s -> %s\n", infile, outfile);
    encryptfile(rc4, infd, outfd, key, size);

    close(infd);
    close(outfd);
    rc4uninit(rc4);
    wipe(key,size);
    free(key);

    return 0;
}