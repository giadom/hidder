
// includiamo tutte le specifiche ds
#include "hidder.h"

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void pass_to_digest( hdr_data* data){
    
    SHA256_CTX sha256;
    SHA256_Init( &sha256 );
    SHA256_Update( &sha256, data->password, strlen(data->password) );
    SHA256_Final(data->digest, &sha256);
    
}


void decrypt_plaintext_len( struct hdr_data_message *data ){
    unsigned int crypt=0;
    unsigned int temp,temp2=0; 
    int i;

    crypt =  ( ( (unsigned int)data->crypted_plaintext_len[0] ) << (3*BYTE_LEN) ) |
             ( ( (unsigned int)data->crypted_plaintext_len[1] ) << (2*BYTE_LEN) ) |
             ( ( (unsigned int)data->crypted_plaintext_len[2] ) << (1*BYTE_LEN) ) |
              (unsigned int)data->crypted_plaintext_len[3];
    

    for( i=0; i< IV_LEN; i+=4){
        temp =( ( ( (unsigned int) (data->ivec[i+0]) ) << (3*BYTE_LEN) ) |
                ( ( (unsigned int) (data->ivec[i+1]) ) << (2*BYTE_LEN) ) |
                ( ( (unsigned int) (data->ivec[i+2]) ) << ( BYTE_LEN ) ) |
                ( ( (unsigned int) (data->ivec[i+3]) ) ) );
        temp2 ^= temp;
    }
    crypt ^= temp2;
    temp2=0;
    for( i=0; i<(DIGEST_LEN/BYTE_LEN); i+=4 ){
        temp =( ( ( (unsigned int) (data->digest[i+0]) ) << (3*BYTE_LEN) ) |
                ( ( (unsigned int) (data->digest[i+1]) ) << (2*BYTE_LEN) ) |
                ( ( (unsigned int) (data->digest[i+2]) ) << ( BYTE_LEN ) ) |
                ( ( (unsigned int) (data->digest[i+3]) ) ) );
        temp2 ^= temp;
    }
    crypt ^= temp2;
    data->plaintext_len=crypt;
}

void encrypt_plaintext_len( unsigned int plaintext_len, unsigned char* digest,unsigned char* ivec, unsigned char* crypt_len ){
    unsigned int crypt=0;
    unsigned int temp,temp2=0;
    int i;
    for( i=0; i< IV_LEN; i+=4){
        temp =( ( ( (unsigned int) (ivec[i+0]) ) << (3*BYTE_LEN) ) |
                ( ( (unsigned int) (ivec[i+1]) ) << (2*BYTE_LEN) ) |
                ( ( (unsigned int) (ivec[i+2]) ) << ( BYTE_LEN ) ) |
                ( ( (unsigned int) (ivec[i+3]) ) ) );
        temp2 ^= temp;
    }
    crypt = temp2 ^ plaintext_len;
    temp2=0;
    for( i=0; i<(DIGEST_LEN/BYTE_LEN); i+=4 ){
        temp =( ( ( (unsigned int) (digest[i+0]) ) << (3*BYTE_LEN) ) |
                ( ( (unsigned int) (digest[i+1]) ) << (2*BYTE_LEN) ) |
                ( ( (unsigned int) (digest[i+2]) ) << ( BYTE_LEN ) ) |
                ( ( (unsigned int) (digest[i+3]) ) ) );
        temp2 ^= temp;
    }
    crypt ^= temp2;
    
    crypt_len[0] = (unsigned char)( ( (unsigned int)crypt ) >> (3*BYTE_LEN) );
    crypt_len[1] = (unsigned char)( ( (unsigned int)crypt ) >> (2*BYTE_LEN) );
    crypt_len[2] = (unsigned char)( ( (unsigned int)crypt ) >> (1*BYTE_LEN) );
    crypt_len[3] = (unsigned char)crypt;
    
}

void get_iv( hdr_data* data ){
    unsigned int seed=0;
    /*
        inizializzo il digest come seed, per non rendere noto il vettore di inizializzazione
        utilizzo i primi 4 byte del digest come intero per il seed
        ES: digest = 18ac3e73435d.... seed = 0x733eac18
    */
    seed =  ( ( (unsigned int) (data->digest[0]) ) |
            ( ( (unsigned int) (data->digest[1]) ) << (BYTE_LEN) ) |
            ( ( (unsigned int) (data->digest[2]) ) << (2*BYTE_LEN) ) |
            ( ( (unsigned int) (data->digest[3]) ) << (3*BYTE_LEN) ) );
    srand( seed );
    int i;
    
}

int encrypt_plaintext( hdr_data* data ){
    
    int i;
    get_iv(data);
    
    data->cyphertext = malloc( sizeof(char)*( data->plaintext_len+AES_BLOCK_SIZE ) );
    if ( data->cyphertext == NULL ){
        write_log("malloc data->cyphertext failed\n");
        sleep(2);
        exit(1);
    }
    
    encrypt_plaintext_len( data->plaintext_len, data->digest, data->ivec, data->crypted_plaintext_len );
    data->cyphertext_len = encrypt( data->plaintext, data->plaintext_len , data->digest,
            data->ivec, data->cyphertext);

    return true;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    /*
        check if padding is needed
    */ 
    if( !( plaintext_len % EVP_CIPHER_CTX_block_size(ctx) ) ){
        EVP_CIPHER_CTX_set_padding( ctx, 0);
        write_log( "padding disabled plaintext_len: %d\n", plaintext_len );
    }

    /*
     * Provide the plaintext to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;
    write_log( "cyphertext_len: %d\n", ciphertext_len);
    /* Clean up */
    // reset, cancella dalla memoria ogni traccia dei dati sensibili di ctx, e poi fa il free.
    EVP_CIPHER_CTX_reset(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
        TODO se mettiamo la parte di codice che elimina il padding quando è multiplo di 16
        per risparmiarci quei 16bytes in piu che sono molti, hydan non lo fa ma usa blocksize di 8
        perche usa BF (blowfish) invece di aes
    */    EVP_CIPHER_CTX_set_padding( ctx, 0);
        
    /*
     * Provide the plaintext to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


int decrypt_cyphertext( hdr_data* data ){
    unsigned char ivec[ IV_LEN ];
    unsigned int seed=0;
    /*
        inizializzo il digest come seed, per non rendere noto il vettore di inizializzazione
        utilizzo i primi 4 byte del digest come intero per il seed
        ES: digest = 18ac3e73435d.... seed = 0x733eac18
    */
    seed =  ( ( (unsigned int) (data->digest[0]) ) |
            ( ( (unsigned int) (data->digest[1]) ) << (BYTE_LEN) ) |
            ( ( (unsigned int) (data->digest[2]) ) << (2*BYTE_LEN) ) |
            ( ( (unsigned int) (data->digest[3]) ) << (3*BYTE_LEN) ) );
    srand( seed );
    int i;
    for( i=0; i< IV_LEN ; i++){
        ivec[i] = (unsigned char) rand();
    }
    unsigned char *outdata = malloc(data->cyphertext_len);
    if ( outdata == NULL ){
        write_log("malloc outdata failed\n");
        sleep(2);
        exit(1);
    }
    int outLen1=0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit( ctx,EVP_aes_128_cbc(),data->digest,ivec);
    EVP_DecryptUpdate( ctx, outdata, &outLen1 , data->cyphertext, data->cyphertext_len);
    
    EVP_DecryptFinal( ctx, (outdata + outLen1), &data->plaintext_len);
    data->plaintext_len += outLen1;

    outdata[data->plaintext_len];
    write_log( "%s\n", outdata);
}


