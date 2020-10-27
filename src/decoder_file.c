// includiamo tutte le specifiche 
#include "hidder.h"

int decoder_elf_main( int mode, FILE* f_input, struct hdr_data_message* hdr_data){
    // variabili multi uso per return cicli e temporanei
    int i,j,ret;
    unsigned char temp;

    hdr_section_c hdr_code;
    hdr_elf_data* input_data = malloc( sizeof(struct hdr_elf_data) );
    if ( input_data == NULL ){
        write_log("malloc input_data failed\n");
        sleep(2);
        exit(1);
    }
    input_data->fd = fileno(f_input);
    /*
    *   in base all'architettura e al tipo chiamiamo la funzione corretta
    */
    if ( mode == HDR_ARCH_32 ){
        CS_MODE = CS_MODE_32;
        input_data->eh32 = malloc( sizeof(Elf32_Ehdr) );
        if ( input_data->eh32 == NULL ){
            write_log("malloc input_data->eh32 failed\n");
            sleep(2);
            exit(1);
        }
        /*
        *   leggo l'header del file
        */
		read_elf_header( input_data->fd, input_data->eh32);

        /*
        *   leggo Section header table : 
        *   e_shentsize è la dimensione di ogni section header
        *   e_shnum è il numero di section header
        */
		input_data->sh32_tbl = malloc( input_data->eh32->e_shentsize * input_data->eh32->e_shnum );
		if(!input_data->sh32_tbl) {
			write_log("Failed to allocate %d bytes\n",
					(input_data->eh32->e_shentsize * input_data->eh32->e_shnum));
                    exit(1);
		}
		read_section_header_table(input_data->fd, *(input_data->eh32), input_data->sh32_tbl);
        
        if( !read_text_section( input_data, &hdr_code ) ){
            write_log("Failed to read code section\n" );
            exit(1);
        }
    }
    if ( mode == HDR_ARCH_64  ){
        CS_MODE = CS_MODE_64;
        input_data->eh64 = malloc( sizeof(Elf64_Ehdr) );
        if ( input_data->eh64 == NULL ){
            write_log("malloc input_data->eh64 failed\n");
            sleep(2);
            exit(1);
        }
        /*
        *   leggo l'header del file
        */
		read_elf_header64( input_data->fd, input_data->eh64);

        /*
        *   leggo Section header table : 
        *   e_shentsize è la dimensione di ogni section header
        *   e_shnum è il numero di section header
        */
		input_data->sh64_tbl = malloc( input_data->eh64->e_shentsize * input_data->eh64->e_shnum );
		if(!input_data->sh64_tbl) {
			write_log("Failed to allocate %d bytes\n",
					(input_data->eh64->e_shentsize * input_data->eh64->e_shnum));
                    exit(1);
		}
		read_section_header_table64(input_data->fd, *(input_data->eh64), input_data->sh64_tbl);
        
        if( !read_text_section( input_data, &hdr_code ) ){
            write_log("Failed to read code section\n" );
            exit(1);
        }
    }
    decoder_disasm( &hdr_code,  hdr_data );

    fclose(f_input);
    free_hdr_data( hdr_data );
    return 0;
}



int decoder_pe_main( int mode, FILE* f_input, struct hdr_data_message* hdr_data){
    // variabili multi uso per return cicli e temporanei
    int i,j,ret;
    unsigned char temp;

    hdr_section_c hdr_code;
    hdr_pe_data* input_data = malloc( sizeof(struct hdr_pe_data) );
    if ( input_data == NULL ){
        write_log("malloc input_data failed\n");
        sleep(2);
        exit(1);
    }
    input_data->fp = f_input;
    /*
    *   in base all'architettura e al tipo chiamiamo la funzione corretta
    */
    if ( mode == HDR_ARCH_32  ){
        CS_MODE = CS_MODE_32;
        input_data->std_field_32 = malloc( sizeof(oh32_standard_field) );
        if ( input_data->std_field_32 == NULL ){
            write_log("malloc input_data->std_field_32 failed\n");
            sleep(2);
            exit(1);
        }
        input_data->win_specific_32 = malloc( sizeof(oh32_windows_specific) );
        if ( input_data->win_specific_32 == NULL ){
            write_log("malloc input_data->win_specific_32 failed\n");
            sleep(2);
            exit(1);
        }
        /*
        *   leggo l'header del file e section header tutto in una volta
        */
		read_pe32_header( input_data );

        if( !read_pe_text_section( input_data, &hdr_code ) ){
            write_log("Failed to read code section\n" );
            exit(1);
        }
    }
    if ( mode == HDR_ARCH_64  ){
        CS_MODE = CS_MODE_64;
        input_data->std_field_64 = malloc( sizeof(oh64_standard_field) );
        if ( input_data->std_field_64 == NULL ){
            write_log("malloc input_data->std_field_64 failed\n");
            sleep(2);
            exit(1);
        }
        input_data->win_specific_64 = malloc( sizeof(oh64_windows_specific) );
        if ( input_data->win_specific_64 == NULL ){
            write_log("malloc input_data->win_specific_64 failed\n");
            sleep(2);
            exit(1);
        }
        /*
        *   leggo l'header del file e section header tutto in una volta
        */
		read_pe64_header( input_data );
        
        if( !read_pe_text_section( input_data, &hdr_code ) ){
            write_log("Failed to read code section\n" );
            exit(1);
        }
    }
    decoder_disasm( &hdr_code,  hdr_data );

    fclose(f_input);
    free_hdr_data( hdr_data );
    return 0;
}