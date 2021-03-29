#ifndef HIDDER_H
#define HIDDER_H

#include <stdio.h>
#include <inttypes.h>

#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#include "hdr_pe.h"
/*
    librerie che necessitano di installazione
*/
// crypto library
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/err.h>
// disassembler library
#include <capstone/capstone.h>
// assembler library
#include <keystone/keystone.h>
// formato elf
#include <elf.h>
// ELF parser
#include "elf-parser.h"


// ====================================================================
// ===============COSTANTI=============================================

#define true     1
#define false    0
#define error   -1

struct contatore{
    int size;
    int add;
    int adc;
    int mov;
    int cmp;
    int sbb;
    int xor;
    int sub_x;
    int add_s;
    int sub;
    int test;
    int and;
    int or;
    int test1;
    int or1;
    int and1;
    int add1;
    int sub1;
    int xor1;
    int cmp1;
    int cmp_rr;
    
    int big8;
    int big16;
    int big32;
    int big64;

};
struct contatore cont_istr;


/*
    costanti utili per capstone / keystone
*/
int CS_MODE; // conterrà la modalità usata se 32 o 64 bit

/*
    costanti utili per register.c
*/
#include "register.h"

/*
    costanti utili per utility.c
*/
#define MAX_INT_TO_STRING_LEN 23 // 2^32-1= 2147483647 = 7FFFFFFF 8byte+1"\0"
#define OPERAND_DELIMITATOR ","

/*
    costanti per toa_s.c 
*/
#include "toa.h"
#define BIT_ALREADY_ENCODED 0

/*
    costanti utili per crypto.c
*/
#define CRYPTED_PLAINTEXT_LEN 8
#define ADDSUB_INSTR_MAX_LEN 50
#define DIGEST_LEN 256 // is 256 becouse we use sha256
#define BYTE_LEN 8
#define IV_LEN 16 // AES usa sempre un vettore di inizializzazione di lunghezza 16
#define INT_BYTES_LEN 4

/*
*   costanti per file_parser.c
*/
#define IDENTIFICATION_BYTE_LEN 5
#define FREAD_FAIL -1
#define FSEEK_FAIL -2
#define NOT_ELF_PE -3
#define WRONG_ARCH -4
#define HDR_ELF_FILE 1
#define HDR_PE_FILE 2
#define HDR_ARCH_32 4
#define HDR_ARCH_64 8
#define CODE_SECTION_NAME_ELF ".text"



// ====================================================================
// ===============STRUTTURE============================================

/*
*   struttura per codice
*/
typedef struct hdr_section_content
{
    unsigned char* CODE;
    int section_size;
    int index; // indice della sezione
    int code_section_number;
}hdr_section_c;

/*
*    struttura per plaintext, ciphertext, digest
*/
typedef struct hdr_data_message
{
    FILE* f_output;
    
    unsigned char* password;
    unsigned char digest[ (DIGEST_LEN/BYTE_LEN) ];
    unsigned char ivec[ IV_LEN ];
    char* plaintext; // testo in chiaro e lunghezza
    int plaintext_len;
    unsigned char* cyphertext; // testo cifrato e lunghezza
    int cyphertext_len;

    unsigned char crypted_plaintext_len[INT_BYTES_LEN];

    uint8_t bit_encoded;
    int byte_encoded_size;
} hdr_data;

/*
*   struct per pe file
*/
typedef struct hdr_pe_data
{
    // variabili fisse sia per PE32 che PE32+
    FILE *fp;
    ms_dos_stub ms_dos;
    coff_file_header coff_header;
    // variabili che differiscono, allochiamo solo quella utilizzata
    oh32_standard_field* std_field_32;
    oh64_standard_field* std_field_64;
    oh32_windows_specific* win_specific_32;
    oh64_windows_specific* win_specific_64;
    data_directory* dt_dir;
    image_section_header* sh_tbl;

}hdr_pe_data;

/*
 *  struttura per file input
 *  contiene tutti i dati del file parsato
*/
typedef struct hdr_elf_data
{
    int fd; // file descriptor del file eseguibile

    Elf64_Ehdr* eh64;	/* elf-header is fixed size */
	Elf64_Shdr* sh64_tbl;	/* section-header table is variable size */

    Elf32_Ehdr* eh32;	/* elf-header is fixed size */
	Elf32_Shdr* sh32_tbl;	/* section-header table is variable size */

}hdr_elf_data;

// ====================================================================
// ===============GLOBAL VAR===========================================
/*
    è usata una struct poichè dentro vanno inseriti altri controlli, per lavori futuri
*/
struct hdr_register{
    unsigned long reg_flag;
};
struct hdr_register registri;
int *lab;
int cont_label;

/*
    Opzioni passate da riga di comando al programma
*/
extern int e_opt_dec; // opzione -e per decoder (e sta per esegui)

// ====================================================================
// ===============FUNCTION=============================================

/*
    utility.c function
*/
void write_log( const char* error_string, ...);
int read_plaintext(char* file_path, hdr_data* data );
uint8_t take_bits( struct hdr_data_message* data, uint8_t num_bits );
void print_reg();
int put_bits( struct hdr_data_message* hdr_data, int ret, uint8_t num_bits);
void free_hdr_data( struct hdr_data_message *data );
void free_elf_data(hdr_elf_data* input_data);
void free_hdr_section_content( struct hdr_section_content data );
void free_global();

/*
    crypto.c function
*/
void pass_to_digest( hdr_data* data );
int encrypt_plaintext( hdr_data* data );
int decrypt_cyphertext( hdr_data* data );
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
void get_iv( hdr_data* data );
void decrypt_plaintext_len( struct hdr_data_message *data );
/*
    toa_s.c function
*/
int toa_subs( cs_insn* insn, int index, int num_ists, struct hdr_data_message *data, unsigned char* output );
int match_insn( cs_insn insn, unsigned char* output );
int toa_is_subs( cs_insn isns );
int match_equivalent_bytes_sets( cs_insn insn, struct hdr_data_message *data, unsigned char* output);
int match_is_sets( cs_insn insn );
/*
    xor_sub_s.c function
*/
int xor_sub_subs( cs_insn isns, struct hdr_data_message *data, unsigned char* output );
int xor_sub_is_subs( cs_insn isns );
/*
    aacms_s.c function
*/
int aacms_s( cs_insn isns, struct hdr_data_message *data, unsigned char* output );
int aacms_is_s( cs_insn isns );
/*
    cmp_rr.c function
*/
int cmp_subs( cs_insn* isns, int index, int num_ists, struct hdr_data_message *data, unsigned char* output);
int cmp_is_subs( cs_insn* insn, int index, int num_ists );
/*
    add/sub_s.c function
*/
int addsub_imm_s( cs_insn* isns, int index, int num_ists, struct hdr_data_message *data, unsigned char* output);
int addsub_imm_is_s( cs_insn* isns, int index, int num_ists);
/*
    file_parser.c function
*/
int which_arch( FILE* fp );
int read_text_section( hdr_elf_data*  input_data, hdr_section_c* hdr_code );
int read_pe_text_section( hdr_pe_data*  input_data, hdr_section_c* hdr_code );
char *get_eflag_name(uint64_t flag);
/*
    reg_flag_check.c function
*/
int check_flag( cs_insn* isns, int flags, int index, int num_ists );
int is_reg( char* str );
void print_reg();
int flag_reg( const char* str);
int hdr_is_RET( int id);
int hdr_is_JUMP( int id);
int hdr_is_CALL( int id);
/*
    main.c function
*/
int hidder_main(int argc, char *argv[]);
int decoder_main(int argc, char *argv[]);
/*
    hidder/decoder_elf.c function
*/
int hidder_elf_main( int mode, FILE* f_input, FILE* f_output, struct hdr_data_message* hdr_data);
int decoder_elf_main( int mode, FILE* f_input, struct hdr_data_message* hdr_data);
int hidder_pe_main( int mode, FILE* f_input, FILE* f_output, struct hdr_data_message* hdr_data);
int decoder_pe_main( int mode, FILE* f_input, struct hdr_data_message* hdr_data);
/*
    pe_parser.c function
*/
int read_pe32_header( struct hdr_pe_data* input_data );
int read_pe64_header( struct hdr_pe_data* input_data );
int stampa( struct optional_header_64_windows_specific *win);
/*
    disassembler.c function
*/
int hidder_disasm( struct hdr_section_content* hdr_code, struct hdr_data_message* hdr_data );
int decoder_disasm( struct hdr_section_content* hdr_code, struct hdr_data_message* hdr_data );
int disasm( unsigned char* CODE, int size);
int is_skipdata( unsigned int id);

#endif

