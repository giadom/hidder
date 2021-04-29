
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

/* Funzione d'utilita`, privata a questo file, che estrapola il contenuto delle code caves
   e lo mette nel secondo argomento. In aggiunta imposta anche cc_total_size. */
static int
get_from_cc(const unsigned char * const cc_file_content , unsigned char * const cyphertext , int *const cc_total_size)
{
    int cc_file_size;
    memcpy(&cc_file_size , cc_file_content , INT_BYTES_LEN);
    /* +1 per conteggiare anche il numero iniziale che indica il numero di elementi nella lista:
       inizio_cc1,byte_cc1,inizio_cc2,byte_cc2,... */
    cc_file_size= (cc_file_size+1)*INT_BYTES_LEN;
    *cc_total_size=0; // Inizializzo la dimensione totale di tutte le code caves
    int inizio; // Indirizzo di partenza della code cave
    int quanti; // Quanti byte sono utilizzati nella code cave
    
    // (Ri)apro il file contenitore; questa volta agisco sulle code caves.
    FILE * const f_input=fopen(c_opt_dec,"rb");
    if(NULL==f_input)
    {
        write_log("Error on opening %s\n in ``get_from_cc\"",c_opt_dec);
        exit(EXIT_FAILURE);
    }
    
    // Inizio dal primo byte che indica l'indirizzo di partenza della prima code cave
    for(size_t posizione=INT_BYTES_LEN ; posizione<cc_file_size ; posizione+=(INT_BYTES_LEN*2))
    {
        memcpy(&inizio , cc_file_content+posizione , INT_BYTES_LEN);
        memcpy(&quanti , cc_file_content+posizione+INT_BYTES_LEN , INT_BYTES_LEN);
        if( 0!=fseek(f_input,inizio,SEEK_SET) )
        {
            write_log("File positioning error of %s in ``get_from_cc\"",c_opt_dec);
            exit(EXIT_FAILURE);
        }
        if( quanti!=fread(cyphertext+(*cc_total_size),sizeof(unsigned char),quanti,f_input) )
        {
            write_log("Error while reading %s in ``get_from_cc\"",c_opt_dec);
            exit(EXIT_FAILURE);
        }
        *cc_total_size+=quanti;
    }
    
    if(EOF==fclose(f_input))
    {
        write_log("Error while closing %s\n in ``get_from_cc\"",c_opt_dec);
        exit(EXIT_FAILURE);
    }
    
    return *cc_total_size;
}

/*
*   ricostruisce il messaggio
*/
int put_bits( struct hdr_data_message* data, int ret, uint8_t num_bits){
    int i,j;
    uint8_t bit = 0;
    
    // La seguente variabile giochera` un ruolo se ho fornito l'opzione -c
    static unsigned char cc_file_size_crypted[INT_BYTES_LEN];
    
    for (i = (num_bits-1); i >= 0; i--)
    {
        if( data->byte_encoded_size < INT_BYTES_LEN){
            data->crypted_plaintext_len[data->byte_encoded_size] <<= 1;
            data->crypted_plaintext_len[data->byte_encoded_size] |= ( (ret & (1<<i)) >>i );
        }
        else if(NULL!=c_opt_dec && (*data).byte_encoded_size>=INT_BYTES_LEN && 0==(*data).cc_file_size)
        {
            /* Devo estrapolare i byte (cifrati) che indicano il numero di elementi nella lista:
               inizio_cc1,byte_cc1,inizio_cc2,byte_cc2,...*/
            cc_file_size_crypted[data->byte_encoded_size-INT_BYTES_LEN] <<= 1;
            cc_file_size_crypted[data->byte_encoded_size-INT_BYTES_LEN] |= ( (ret & (1<<i)) >>i );
        }
        else if(NULL!=c_opt_dec && (*data).byte_encoded_size-INT_BYTES_LEN<(*data).cc_file_size )
        {
            // Inizio a mettere dai byte successivi ai byte che indicano il numero di elementi nella lista...
            (*data).cc_file_content_crypted[ (*data).byte_encoded_size-INT_BYTES_LEN ] <<= 1;
            (*data).cc_file_content_crypted[ (*data).byte_encoded_size-INT_BYTES_LEN ] |= ( (ret & (1<<i)) >>i );
        }
        else{
            /*
            A byte_encoded_size:
            - si sottrae INT_BYTES_LEN perche' devo togliere dal conteggio quei byte che ho nascosto per crypted_plaintext_len
            - si sottrae (*data).cc_file_size perche' devo togliere dal conteggio quegli eventuali byte che ho estrapolato
              per individuare le informazioni utili all'utilizzo delle code caves
            */
            data->cyphertext[data->byte_encoded_size-INT_BYTES_LEN-(*data).cc_file_size] <<= 1;
            data->cyphertext[data->byte_encoded_size-INT_BYTES_LEN-(*data).cc_file_size] |= ( (ret & (1<<i)) >>i );
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
            else if( NULL!=c_opt_dec && INT_BYTES_LEN*2==(*data).byte_encoded_size /*data->bit_encoded==0 e` sempre vero*/ )
            {
                /*
                Se mi e` stata fornita l'opzione -c e sono arrivato ad estrapolare il secondo intero, allora decifro la
                lunghezza di cc_file_size con la funzione in crypto.c
                */
                (*data).cc_file_size=decrypt_cc_file_size(cc_file_size_crypted);
                (*data).cc_file_content_crypted=(unsigned char *)malloc((*data).cc_file_size*sizeof(unsigned char));
                if(NULL == (*data).cc_file_content_crypted)
                {
                    write_log("malloc (*data).cc_file_content_crypted failed in ``put_bits\"\n");
                    exit(EXIT_FAILURE);
                }
                // Per coerenza, metto in cc_file_content_crypted anche cc_file_size_crypted
                memcpy((*data).cc_file_content_crypted , cc_file_size_crypted ,INT_BYTES_LEN);
            }
            else if(NULL!=c_opt_dec && (*data).byte_encoded_size-INT_BYTES_LEN==(*data).cc_file_size /*data->bit_encoded==0 e` sempre vero*/)
            {
                /*
                Se mi e` stata fornita l'opzione -c e sono arrivato ad estrapolare l'ultimo byte delle informazioni utili
                all'utilizzo delle code caves, allora:
                */
                // 1) Decifro tutta l'informazione utile all'utilizzo delle code caves;
                (*data).cc_file_content=decrypt_cc_file_content((*data).cc_file_content_crypted , (*data).cc_file_size);
                // 2) Estrapolo cio` che e` stato nascosto nelle code caves e lo metto in cyphertext;
                //    sommo i byte estrapolati a byte_encoded_size
                (*data).byte_encoded_size+=get_from_cc((*data).cc_file_content , (*data).cyphertext , &(*data).cc_total_size);
                // A questo punto byte_encoded_size sara` uguale a INT_BYTES_LEN + (*data).cc_file_size + (*data).cc_total_size
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
        }
        else if( (*data).byte_encoded_size-INT_BYTES_LEN < (*data).cc_file_size )
        {
            // N.B.: se (*data).cc_file_size==0 (ossia il default), qui non entro mai
            bit |= ( ( (*data).cc_file_content_crypted[data->byte_encoded_size-INT_BYTES_LEN] & '\x80' ) >> 7 ) ;
            (*data).cc_file_content_crypted[data->byte_encoded_size-INT_BYTES_LEN] <<= 1;
        }
        else{
            /* 
            A byte_encoded_size:
            - si sottrae INT_BYTES_LEN perche' devo togliere dal conteggio quei byte che ho nascosto per crypted_plaintext_len
            - si sottrae cc_file_size perche' devo togliere dal conteggio quei byte che ho nascosto per cc_file_content (eventualmente 0)
            */
            bit |= ( ( data->cyphertext[data->byte_encoded_size - INT_BYTES_LEN - data->cc_file_size] & '\x80' ) >> 7 );
            data->cyphertext[data->byte_encoded_size - INT_BYTES_LEN - data->cc_file_size] <<= 1;
        }
        // in caso finisco il byte attuale, passo al byte successivo
        if( ( data->bit_encoded++ ) == 7  ){
            data->byte_encoded_size++;
            data->bit_encoded=0;
            
            if((*data).byte_encoded_size-INT_BYTES_LEN == (*data).cc_file_size)
            {
                /*
                Quando entro qui ho finito di nascondere anche cc_file_content_crypted. A questo punto passo a nascondere
                quei byte che NON andranno nelle code caves; par dire cio`, abbono i primi (*data).cc_total_size-byte
                di messaggio cifrato
                */
                (*data).byte_encoded_size+=(*data).cc_total_size;
            }
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

/*
Imposto la variabile cc_total_size con questa funzione privata d'utilita`.
Utilizzo const e puntatori per aumentare la velocita` e diminuire i privilegi.
*/
static void
set_cc_total_size(const int *const cc_file_size , int *const cc_total_size ,\
                  const unsigned char *const cc_file_content , const int *const cyphertext_len)
{
    int tmp;
    // mi posiziono all'inizio del terzo intero di cc_file_content: quello che indica la prima dimensione della prima cc;
    // ciclo fintantoche' ci sono dimensioni da sommare ;
    // dopo ogni ciclo mi posiziono all'inizio dell'intero raffigurante la dimensione della prossima cc
    for(int i=INT_BYTES_LEN*2 ; i<*cc_file_size ; i+=(INT_BYTES_LEN*2) )
    {
        memcpy(&tmp , (cc_file_content)+i , INT_BYTES_LEN);
        *cc_total_size+=tmp;
    }
    
    if(*cc_total_size>*cyphertext_len)
    {
        write_log("Error: you are trying to hide inside code caves more bytes then cyphertext length\n");
        exit(EXIT_FAILURE);
    }
}

/*
Funzione che legge il contenuto (ben formattato) di output_setaccio.bin e ritorna il puntatore alla memoria
principale che contiene tale contenuto
*/
unsigned char *
read_cc_file(hdr_data * const data)
{
    FILE *const STREAM=fopen(c_opt_hid,"rb");
    if(NULL==STREAM)
    {
        write_log("Error on opening %s\n",c_opt_hid);
        exit(EXIT_FAILURE);
    }
    int cc; // Questa variabile conterra` il numero di elementi nella lista formata da:
            // indirizzo_partenza_cc1,lunghezza_in_byte1,indirizzo_partenza_cc2,lunghezza_in_byte2,...
    if(1!=fread(&cc,INT_BYTES_LEN,1,STREAM))
    {
        write_log("Error while reading %s\n",c_opt_hid);
        exit(EXIT_FAILURE);
    }
    rewind(STREAM);
    
    /*
    Indica il numero di byte da leggere nel file e dunque da allocare per contenerli.
    Faccio +1 per conteggiare anche il valore attualmente assunto da cc.
    */
    (*data).cc_file_size=(cc+1)*INT_BYTES_LEN;
    unsigned char *const cc_file_content=(unsigned char *)malloc( sizeof(unsigned char)*(*data).cc_file_size );
    if(NULL==cc_file_content)
    {
        write_log("Error: malloc failed for code caves file content\n");
        exit(EXIT_FAILURE);
    }
    
    if( (*data).cc_file_size != fread(cc_file_content,sizeof(unsigned char),(*data).cc_file_size,STREAM) )
    {
        write_log("Error while reading %s\n",c_opt_hid);
        exit(EXIT_FAILURE);
    }
    if(EOF==fclose(STREAM))
    {
        write_log("Error while closing %s\n",c_opt_hid);
        exit(EXIT_FAILURE);
    }

    set_cc_total_size( &((*data).cc_file_size) , &((*data).cc_total_size) , cc_file_content , &((*data).cyphertext_len));
    return cc_file_content;
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
    if(NULL!=c_opt_hid || NULL!=c_opt_dec)
    {
        // Spiano a zero per davvero (a differenza di memset e bzero). Si trova in string.h
        explicit_bzero( (*data).cc_file_content , (*data).cc_file_size );
        explicit_bzero( (*data).cc_file_content_crypted , (*data).cc_file_size );
        (*data).cc_file_size=0;
        (*data).cc_total_size=0;
        free((*data).cc_file_content);
        free((*data).cc_file_content_crypted);
    }
    free(data);
}

void free_hdr_section_content( struct hdr_section_content data ){
    free(data.CODE);
}

void free_global(){
    free(lab);
}


