#include "../myCrypto.h"
int main ( int argc , char * argv[] )
{
    uint8_t digest[EVP_MAX_MD_SIZE] ;
    int     i , fd_in , fd_ctrl , fd_data  ;
    size_t  mdLen ;
    FILE    *log ;
    
    char *developerName = "Noah Kaiser" ;

    printf( "\nThis is Amal's   REFERENCE Code By: %s\n\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    
    fd_ctrl   = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Amal: Could not create log file\n");
        exit(-1) ;
    }

    fprintf( log , "\nThis is Amal's   REFERENCE Code By: %s.\n" , developerName  ) ;
    fprintf( log , "\nAmal: I Will send digest to FD %d and file to FD %d\n" , fd_ctrl, fd_data);
    fprintf( log , "Amal: Starting to digest the input file\n");
    // compute digest and send video to basim
    fd_in = open("bunny.mp4" , O_RDONLY , S_IRUSR | S_IWUSR ) ;
    mdLen = fileDigest(fd_in, fd_data, digest);

    fprintf( log, "\nAmal: Here is the digest of the file:\n");
    BIO_dump_fp(log, (const char *) digest, mdLen);
       
    // send encrypted digest to basim
    RSA  *privateKey =  getRSAfromFile( "amal/amal_priv_key.pem" , 0 ) ;
    uint8_t *signature = malloc( RSA_size( privateKey ) ) ; 
    int sig_len  
        = RSA_private_encrypt( mdLen, digest, signature, privateKey 
                              , RSA_PKCS1_PADDING );
    write(fd_ctrl, signature, sig_len);

    fprintf( log, "\nAmal: Here is the signature of the file:\n");
    BIO_dump_fp(log, (const char *) signature, sig_len);

    // Close any open files / descriptors,  free any dynamic memory
    fflush(log);
    fclose(log);
    close(fd_in);
    // Clean up the crypto library
    RSA_free(privateKey) ;
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();

}