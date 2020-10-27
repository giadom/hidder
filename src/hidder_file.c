// includiamo tutte le specifiche 
#include "hidder.h"

int hidder_elf_main( int mode, FILE* f_input,FILE* f_output, struct hdr_data_message* hdr_data){
    // variabili multi uso per return cicli e temporanei
    int i,j,ret;
    unsigned char temp;

    hdr_elf_data* input_data = malloc( sizeof(struct hdr_elf_data) );
    if ( input_data == NULL ){
        write_log("malloc input_data failed\n");
        sleep(2);
        exit(1);
    }
    
    input_data->fd = fileno(f_input);
    hdr_section_c hdr_code;
    /*
    *   in base all'architettura e al tipo chiamiamo la funzione corretta
    */
    if ( mode == HDR_ARCH_32  ){
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
            exit(5);
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
        input_data->fd = fileno(f_input);
        /*
        *   leggo l'header del file
        */
		read_elf_header64( input_data->fd, input_data->eh64);

        /*
        *   leggo Section header table: 
        *   e_shentsize è la dimensione di ogni section header
        *   e_shnum è il numero di section header
        */
		input_data->sh64_tbl = malloc( input_data->eh64->e_shentsize * input_data->eh64->e_shnum );
		if(!input_data->sh64_tbl) {
			write_log("Failed to allocate %d bytes\n",
					(input_data->eh64->e_shentsize * input_data->eh64->e_shnum));
            exit(5);
		}
		read_section_header_table64(input_data->fd, *(input_data->eh64), input_data->sh64_tbl);
        
        if( !read_text_section( input_data, &hdr_code ) ){
            write_log("Failed to read code section\n" );
            exit(1);
        }

    }
    // inizializzo le variabili per salvare le label (iniziamo con 50 ma reallochiamo man mano)
    lab = (int *)malloc( 50*sizeof(int) );
    if ( lab == NULL ){
        write_log("malloc lab failed\n");
        return error;
    }
    cont_label=0;
    
    disasm( hdr_code.CODE, hdr_code.section_size );
    hidder_disasm( &hdr_code, hdr_data );

    if( hdr_data->byte_encoded_size < hdr_data->cyphertext_len ){
        write_log("Encoded %d/%d bytes rate %d, cambia file oppure riduci il messaggio\n", 
                    hdr_data->byte_encoded_size, hdr_data->cyphertext_len, (cont_istr.size/hdr_data->byte_encoded_size)  );
    }
    if( fseek(f_input,0,SEEK_SET) < 0){
        write_log("fseek errore\n");
        return -1;
    }

    if ( mode == HDR_ARCH_32  ){
        // copio in f_output tutto cio che precede il segmento contenente il codice
        for( i=0; i < input_data->sh32_tbl[hdr_code.index].sh_offset ;i++){
            fread(&temp, 1, 1, f_input);
            fwrite(&temp, 1, 1, f_output);
        }

        fwrite( hdr_code.CODE, hdr_code.section_size, 1, f_output);
        fseek(f_input, (input_data->sh32_tbl[hdr_code.index].sh_offset + hdr_code.section_size) , SEEK_SET);
        int xc=0;
        do{
            xc = fread(&temp, 1, 1, f_input);
            if( (xc!=1) && ( (feof(f_input) ) || ferror(f_input) ) ) break;
            fwrite(&temp, 1, 1, f_output);
        }while( true );
    }
    if ( mode == HDR_ARCH_64  ){
        // copio in f_output tutto cio che precede il segmento contenente il codice
        for( i=0; i < input_data->sh64_tbl[hdr_code.index].sh_offset ;i++){
            fread(&temp, 1, 1, f_input);
            fwrite(&temp, 1, 1, f_output);
        }

        fwrite( hdr_code.CODE, hdr_code.section_size, 1, f_output);
        fseek(f_input, (input_data->sh64_tbl[hdr_code.index].sh_offset + hdr_code.section_size) , SEEK_SET);
        int xc=0;
        do{
            xc = fread(&temp, 1, 1, f_input);
            if( (xc!=1) && ( (feof(f_input) ) || ferror(f_input) ) ) break;
            fwrite(&temp, 1, 1, f_output);
        }while( true );
    }

    free_hdr_section_content( hdr_code );
    free_elf_data( input_data );
    return 0;
}



int hidder_pe_main( int mode, FILE* f_input,FILE* f_output, struct hdr_data_message* hdr_data){
    // variabili multi uso per return cicli e temporanei
    int i,j,ret;
    unsigned char temp;

    hdr_pe_data* input_data = malloc( sizeof(struct hdr_pe_data) );
    if ( input_data == NULL ){
        write_log("malloc input_data failed\n");
        sleep(2);
        exit(1);
    }
    input_data->fp = f_input;
    hdr_section_c hdr_code;
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
    // inizializzo le variabili per salvare le label (iniziamo con 50 ma reallochiamo man mano)
    lab = (int *)malloc( 50*sizeof(int) );
    if ( lab == NULL ){
        write_log("malloc lab failed\n");
        return error;
    }
    cont_label=0;
    disasm(hdr_code.CODE,hdr_code.section_size);
    hidder_disasm(  &hdr_code,  hdr_data );
    
    if( hdr_data->byte_encoded_size < hdr_data->cyphertext_len ){
            write_log("Encoded %d/%d bytes rate %d, cambia file oppure riduci il messaggio\n", hdr_data->byte_encoded_size, 
                hdr_data->cyphertext_len, hdr_data->byte_encoded_size==0?0:(cont_istr.size/hdr_data->byte_encoded_size)  );
    }
    if( fseek(f_input,0,SEEK_SET) < 0){
        write_log("fseek errore\n");
        return -1;
    }
    
    // copio in f_output tutto cio che precede il segmento contenente il codice
    for( i=0; i < input_data->sh_tbl[hdr_code.index].PointerToRawData ;i++){
        fread(&temp, 1, 1, f_input);
        fwrite(&temp, 1, 1, f_output);
    }

    fwrite( hdr_code.CODE, hdr_code.section_size, 1, f_output);
    fseek(f_input, (input_data->sh_tbl[hdr_code.index].PointerToRawData + hdr_code.section_size) , SEEK_SET);
    int xc=0;
    do{
        xc = fread(&temp, 1, 1, f_input);
        if( (xc!=1) && ( (feof(f_input) ) || ferror(f_input) ) ) break;
        fwrite(&temp, 1, 1, f_output);
    }while( true );


    free_hdr_section_content( hdr_code );
    return 0;

}