
// includiamo tutte le specifiche
#include "hidder.h"


void write_log( const char* error_string, ...) {
	va_list args;
	va_start(args, error_string);
	#define LOG_STR_LEN 1024

	char* formatted_error_string = malloc(LOG_STR_LEN);
	if( formatted_error_string == NULL ){
		fprintf(stdout, "Malloc on writelog failed becouse: %s", strerror(errno));
        fflush(stdout);
		exit(5);
	}

	vsnprintf(formatted_error_string, LOG_STR_LEN, error_string, args);

	// make sure that the string ends with no trailing newlines ('\n')
	/*if(formatted_error_string[strlen(formatted_error_string)-1] == '\n') {
		formatted_error_string[strlen(formatted_error_string)-1] = '\0';
	}*/

	fprintf(stdout, "%s", formatted_error_string);
	fflush(stdout);
	
	free(formatted_error_string);
	va_end(args);
}

/*
*   ricostruisce il messaggio
*/
int put_bits( struct hdr_data_message* data, int ret, uint8_t num_bits){
    int i,j;
    uint8_t bit = 0;
    
    for (i = (num_bits-1); i >= 0; i--)
    {
        if( data->byte_encoded_size < INT_BYTES_LEN){
            data->crypted_plaintext_len[data->byte_encoded_size] <<= 1;
            data->crypted_plaintext_len[data->byte_encoded_size] |= ( (ret & (1<<i)) >>i );
        }else{
            data->cyphertext[data->byte_encoded_size-INT_BYTES_LEN] <<= 1;
            data->cyphertext[data->byte_encoded_size-INT_BYTES_LEN] |= ( (ret & (1<<i)) >>i );
        }
        // in caso finisco il byte attuale, passo al byte successivo
        if( ( data->bit_encoded++ ) == 7  ){
            data->byte_encoded_size++;
            data->bit_encoded=0;
            
            if( (data->byte_encoded_size == INT_BYTES_LEN)&&(data->bit_encoded==0) ){
                decrypt_plaintext_len( data );
                data->cyphertext = malloc( (data->plaintext_len+AES_BLOCK_SIZE) );
                if ( data->cyphertext == NULL ){
                    write_log("malloc data->ciphertext failed\n");
                    sleep(2);
                    exit(1);
                }
                data->cyphertext_len = data->plaintext_len+ ( AES_BLOCK_SIZE-(data->plaintext_len%AES_BLOCK_SIZE));
            }
        }
    }
    
}


/*
*   ritorna un uint8, rappresenzante gli n* bit richiesti.
*/
uint8_t take_bits( struct hdr_data_message* data, uint8_t num_bits ){
    
    int i,j;
    uint8_t bit = 0;
    for (i = 0; i < num_bits; i++)
    {
        /*
        *   prendo l'ultimo bit del messaggio, shifto i bit di ritorno di 1 a sinistra e
        *   metto come primo bit il bit del messaggio.
        *   ES byte mes:  1011 0001 byte ritorno: 0000 0101, 
        *   prendo 1 e shifto a sinistra mex diventando 0110 0010 (aggiunge 0 a sinistra)
        *   shifto a sinistra byte ritorno e diventa 0000 1010,  
        *   metto il bit preso in prima pos e ottengo 0000 1011 e lo ritorno.
        */
        bit <<= 1;
        if( data->byte_encoded_size < INT_BYTES_LEN ){
            bit |= ( ( data->crypted_plaintext_len[data->byte_encoded_size] & '\x80' ) >> 7 );
            data->crypted_plaintext_len[data->byte_encoded_size] <<= 1;
        }else{
            bit |= ( ( data->cyphertext[data->byte_encoded_size-INT_BYTES_LEN] & '\x80' ) >> 7 );
            data->cyphertext[data->byte_encoded_size-INT_BYTES_LEN] <<= 1;
        }
        // in caso finisco il byte attuale, passo al byte successivo
        if( ( data->bit_encoded++ ) == 7  ){
            data->byte_encoded_size++;
            data->bit_encoded=0;
        }
    }
    return bit; 
}

int read_plaintext(char* file_path, hdr_data* data ){
    
	int fd;
	struct stat sta;

    if ( (fd = open (file_path, O_RDONLY)) < 0)
    {
        perror ("open");
        return false;
    }

    if (fstat (fd, &sta) < 0)
    {
        perror ("fstat");
        return false;
    }
    if( sta.st_size > INT_MAX ){
        write_log("dimensione input troppo grande\n");
        return false;
    }
    data->plaintext_len = sta.st_size;
    //data->padding = AES_BLOCK_SIZE - ( data->plaintext_len % AES_BLOCK_SIZE );

    //if ( !( data->plaintext = malloc( sizeof(char)*(data->plaintext_len+data->padding)+1 ) ) )
    if ( !( data->plaintext = malloc( sizeof(char)*(data->plaintext_len+1) ) ) )
    {
        write_log("malloc data->plaintext failed\n");
        return false;
    }

    if (read (fd, data->plaintext, data->plaintext_len) < 0)
    {
        write_log("read data->plaintext failed\n");
        return false;
    }
    /*int i;
    for ( i = 0; i <= data->padding; i++ )
    {
        data->plaintext[ (data->plaintext_len+i) ] = 'a';
    }
    data->plaintext[ (data->plaintext_len+data->padding)+1 ] = '\0';
    */ 
    data->plaintext[ data->plaintext_len ] = '\0';
    close (fd);
	return true;
}


void free_elf_data(hdr_elf_data* input_data){
    if( CS_MODE == CS_MODE_32){
        free( input_data->eh32);
        free(input_data->sh32_tbl);
    }
    if( CS_MODE == CS_MODE_64){
        free( input_data->eh64);
        free(input_data->sh64_tbl);
    }
    free(input_data);
}

void free_hdr_data( struct hdr_data_message *data ){
    
    free(data->cyphertext);
    free(data->password);
    free(data);
}

void free_hdr_section_content( struct hdr_section_content data ){
    free(data.CODE);
}

void free_global(){
    free(lab);
}


