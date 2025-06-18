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
        t->c_lflag != ECHO;
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
    #pragma GCC diagnostic ignored "-Wstringop-truncation"
        strncpy((char *)p, (char *)buf, size);
    #pragma GCC diagnostic pop

    return p;
}

void keyhash(Arcfour *rc4, int fd, int8 *key, int16 size) {
    return;
}

void padding(Arcfour *rc4, int fd, int16 size) {
    return;
}

void addheader(Arcfour *rc4,int fd, int8 *key,int16 size) {
    return;
}

void decryptfile(Arcfour *rc4, int outfd, int infd) {
    return;
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
    printf("Beginning encryption...",infile,outfile); F;
    encryptfile(rc4, outfd, infd, key, size);

    close(infd);
    close(outfd);
    rc4uninit(rc4);
    wipe(key,size);
    free(key);

    return 0;
}