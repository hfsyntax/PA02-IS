/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   myCrypto.c

Written By: 
     1- Noah Kaiser
     2-
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// LAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{
	int status;
	unsigned len=0, encryptedLen=0;
	
	/* Create  and initialise the context */
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if( !ctx )
		handleErrors( "encrypt: failed to create CTX" );

	// Initialise the encryption operation.
	status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv );
	if( status != 1 )
		handleErrors( "encrypt: failed to EncryptUpdate" );
	
	// Call EncryptUpdate as many times as needed (e.g. inside a loop)
	// to perform regular encryption
	status = EVP_EncryptUpdate( ctx, pCipherText, &len, pPlainText, plainText_len );
	if( status != 1 )
		handleErrors( "encypt: fail to EncryptUpdate" );
	encryptedLen += len;
	
	// If additional ciphertext may still be generated,
	// the pCipherText pointer must be first advanced forward
	pCipherText += len;
	
	// Finalize the encryption.
	status = EVP_EncryptFinal_ex( ctx, pCipherText, &len );
	if( status != 1 )
		handleErrors( "encrypt: failed to EncryptFinal_ex" );
	encryptedLen += len;	// len could be 0 if no additional cipher text was generated
	
	/*	Clean up */
	EVP_CIPHER_CTX_free( ctx );
	
	return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
	int status;
	unsigned len = 0, decryptedLen = 0;
	
	/* Create and initialise the context */
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if( !ctx )
		handleErrors( "decrypt: Failed to treat CTX" );
	
	// Initialise the decryption operation.
	status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv );
	if( status != 1 )
		handleErrors( "encrypt: failed to Decrypt_ex" );
	
	// Call DecryptUpdate as many times as needed (e.g. inside a loop)
	// to perform regular decryption
	status = EVP_DecryptUpdate( ctx, pDecryptedText, &len, pCipherText, cipherText_len );
	if( status != 1 )
		handleErrors( "decrypt: fail to DecryptUpdate" );
	decryptedLen += len;
	
	// If additional decrypted text may still be generated,
	// the pDecryptedText pointer must be first advanced forward
	pDecryptedText += len;
	
	// Finalize the decryption.
	status = EVP_DecryptFinal_ex( ctx, pDecryptedText, &len );
	if( status != 1 )
		handleErrors( "decrypt: failed to DecryptFinal_ex" );
	decryptedLen += len;	// len could be 0 if no additional cipher text was generated
	
	/*	Clean up */
	EVP_CIPHER_CTX_free( ctx );
	
	return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************
static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , 
                       ciphertext[ CIPHER_LEN_MAX    ] ,
                       decryptext[ DECRYPTED_LEN_MAX ] ;

int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int status;
    unsigned len = 0, encryptedLen = 0;
    int bytes;

    /* Create  and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if( !ctx )
        handleErrors( "encrypt: failed to create CTX" );

    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv );
    if( status != 1 )
        handleErrors( "encrypt: failed to EncryptUpdate" );

    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    while (bytes != 0)
    {
        // Call EncryptUpdate as many times as needed (e.g. inside a loop)
        // to perform regular encryption
        bytes = read( fd_in, plaintext, PLAINTEXT_LEN_MAX );
        status = EVP_EncryptUpdate( ctx, ciphertext, &len, plaintext, bytes );
        if( status != 1 )
            handleErrors( "encypt: fail to EncryptUpdate" );
        encryptedLen += len;
        write(fd_out, ciphertext, len);
    }

    // Finalize the encryption.
    status = EVP_EncryptFinal_ex( ctx, ciphertext, &len );
    if( status != 1 )
        handleErrors( "encrypt: failed to EncryptFinal_ex" );
    encryptedLen += len;    // len could be 0 if no additional cipher text was generated
    write( fd_out, ciphertext, len );

    /*    Clean up */
    EVP_CIPHER_CTX_free( ctx );
    return encryptedLen;
}

//-----------------------------------------------------------------------------
int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
	int status;
    unsigned len = 0, decryptedLen = 0;
	int bytes;
    
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if( !ctx )
        handleErrors( "decrypt: Failed to treat CTX" );
    
    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv );
    if( status != 1 )
        handleErrors( "encrypt: failed to Decrypt_ex" );
    
    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    while (bytes != 0)
    {
        bytes = read( fd_in, ciphertext, CIPHER_LEN_MAX );
        status = EVP_DecryptUpdate( ctx, decryptext, &len, ciphertext, bytes );
        if( status != 1)
            handleErrors( "decrypt: fail to DecryptUpdate" );
        decryptedLen += len;
        write( fd_out, decryptext, len );
    }
    
    // Finalize the decryption.
    status = EVP_DecryptFinal_ex( ctx, decryptext, &len );
    if( status != 1 )
        handleErrors( "decrypt: failed to DecryptFinal_ex" );
    decryptedLen += len;    // len could be 0 if no additional cipher text was generated
    write( fd_out, decryptext, len );
    
    /*    Clean up */
    EVP_CIPHER_CTX_free( ctx );
    
    return decryptedLen;

}

//***********************************************************************
// LAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
	RSA * rsa;
    // open the binary file whose name is 'filename' for reading
    FILE *rsa_key = fopen(filename, "rb");
    // Create a new RSA object using RSA_new() ;
    rsa = RSA_new();
    // if( public ) read a public RSA key into 'rsa'.  Use PEM_read_RSA_PUBKEY()
    if (public) {
        rsa = PEM_read_RSA_PUBKEY(rsa_key, &rsa, 0, 0);
    }
    // else read a private RSA key into 'rsa'. Use PEM_read_RSAPrivateKey()
    else {
        rsa = PEM_read_RSAPrivateKey(rsa_key, &rsa, 0, 0);
    }
    // close the binary file 'filename'
    fclose(rsa_key);

    return rsa;
}

//***********************************************************************
// PA-02
//***********************************************************************

size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, write a copy of the incoming data stream
// file to 'fd_out'
// Returns actual size in bytes of the computed hash (a.k.a. digest value)
{
    int status;
    unsigned len = 0, fileLen = 0;
    unsigned char ptext [INPUT_CHUNK];
    int bytes = 1;

	// Use EVP_MD_CTX_create() to create new hashing context
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if (!ctx )
		handleErrors("failed to create hasing context");
    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the EVP_sha256() hashing function 
	status = EVP_DigestInit(ctx, EVP_sha256());
	if (status != 1) 
		handleErrors("failed to initialize context");
	while ( bytes != 0 )
    {
        // read( fd_in, ...  , INPUT_CHUNK );
		bytes = read(fd_in, ptext, INPUT_CHUNK);

		// Use EVP_DigestUpdate() to hash the data you read
		status = EVP_DigestUpdate(ctx, ptext, bytes);

        if( status != 1 )
            handleErrors( "failed to update digest hash" );

        if (fd_out > 0)
            write(fd_out, ptext, bytes);
    }

    // Finialize the hash calculation using EVP_DigestFinal() directly
	// into the 'digest' array
    status = EVP_DigestFinal(ctx, digest, &fileLen);

    if( status != 1 )
        handleErrors("failed to final digest hash" );

    // Use EVP_MD_CTX_destroy( ) to clean up the context
    EVP_MD_CTX_destroy(ctx);
    // return the length of the computed digest in bytes ;
    return fileLen;
}