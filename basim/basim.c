#include "../myCrypto.h"
int main ( int argc , char * argv[] )
{
    uint8_t digest[EVP_MAX_MD_SIZE] ;
    int     i , fd_in , fd_ctrl , fd_data  ;
    size_t  mdLen ;
    FILE    *log ;
    
    char *developerName = "Noah Kaiser" ;
    
    printf( "\nThis is Basim's   REFERENCE Code By: %s\n\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    
    fd_ctrl   = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Basim: Could not create log file\n");
        exit(-1) ;
    }

    fprintf( log , "\nThis is Basim's   REFERENCE Code By: %s.\n" , developerName  ) ;
    fprintf( log , "\nBasim: I Will recieve digest from FD %d and file from FD %d\n" , fd_ctrl, fd_data);
    fprintf( log , "Basim: Starting to receive incoming file and compute its digest\n");
    // compute digest of video file sent from basim
    fd_in = open("./bunny.cpy" , O_WRONLY | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR);
    mdLen = fileDigest(fd_data, fd_in, digest);
    
    fprintf( log, "\nBasim: Here is locally-computed the digest of the incoming file:\n");
    BIO_dump_fp(log, (const char *) digest, mdLen);


    // validate signature
    RSA *publicKey =  getRSAfromFile( "basim/amal_pubKey.pem" , 1 ) ;
    int pubKey_len = RSA_size( publicKey ) ;
    uint8_t *signature = malloc( pubKey_len ) ;
    uint8_t *hash = malloc( pubKey_len ) ;
    read(fd_ctrl, signature, pubKey_len);

    fprintf( log, "\nBasim: I received the following signature from Amal:\n");
    BIO_dump_fp(log, (const char *) signature, pubKey_len);
    
    int hash_len  
        = RSA_public_decrypt(pubKey_len, signature, hash, publicKey, RSA_PKCS1_PADDING);
    
    fprintf( log, "\nBasim: Here is Amal's decrypted signature:\n");
    BIO_dump_fp(log, (const char *) hash, hash_len);

    if (hash_len == mdLen && memcmp(hash, digest, hash_len) == 0) {
        fprintf( log, "\n\nBasim: Amal's signature is VALID\n");
    } else {
        fprintf( log, "\n\nBasim: Amal's signature is INVALID\n");
    }

    // Close any open files / descriptors,  free any dynamic memory
    fflush(log);
    fclose(log);
    close(fd_in);
    // Clean up the crypto library
    RSA_free(publicKey) ;
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();

}