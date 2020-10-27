// includiamo tutte le specifiche ds
#include "hidder.h"


int which_arch( FILE* fp ){
	
    uint8_t byte[ IDENTIFICATION_BYTE_LEN ];
    /*
     *  leggiamo i primi 5 byte che determinano se è un elf 32/64 bit
     *  i primi 4 bytes EI_MAG determinano l'elf, il byte successivo EI_CLASS l'arch 
    */
    if( fread( byte, 1, IDENTIFICATION_BYTE_LEN, fp) < IDENTIFICATION_BYTE_LEN ){
        write_log( "fread which_arch() fail\n");
        return FREAD_FAIL;
    }
    /* riporta il file pointer all'inizio */
  	if( fseek(fp,0,SEEK_SET) != 0 ){
        write_log( "fseek which_arch() fail\n");
        return FSEEK_FAIL;
    }
    /*
     *  controllo se ELF e arch
    */
    int i;
    
    if( (byte[EI_MAG0]==ELFMAG0) && (byte[EI_MAG1]==ELFMAG1) && 
        (byte[EI_MAG2]==ELFMAG2) && (byte[EI_MAG3]==ELFMAG3) ){
        
        if( byte[EI_CLASS]==ELFCLASS32 ){
            return (HDR_ARCH_32 | HDR_ELF_FILE);
        }
        if( byte[EI_CLASS]==ELFCLASS64 ){
            return (HDR_ARCH_64 | HDR_ELF_FILE);
        }
        write_log( "wrong arch on input file\n");
        return WRONG_ARCH;
    }

    /*
     *  controllo se PE e arch
    */
    ms_dos_stub ms_dos;
    coff_file_header coff_header;
	uint8_t magic[2];
   	/*
     *  leggiamo DOS header che determina il punto di partenza del COFF header
    */
    if( fread( &ms_dos, 1, sizeof(ms_dos), fp) < sizeof(ms_dos) ){
        write_log( "fread PE which_arch() fail\n");
        return FREAD_FAIL;
    }
	/* riporta il file pointer all'inizio */
  	if( fseek( fp, ms_dos.offset_signature, SEEK_SET) != 0 ){
        write_log( "fseek which_arch() fail\n");
        return FSEEK_FAIL;
    } 
	/*
     *  leggiamo COFF header che determina se PE
    */
    if( fread( &coff_header, 1, sizeof(coff_header), fp) < sizeof(coff_header) ){
        write_log( "fread PE which_arch() fail\n");
        return FREAD_FAIL;
    }
	/*
     *  leggiamo il Magic che determina se PE32 o PE32+
    */
    if( fread( magic, 1, sizeof(magic), fp) < sizeof(magic) ){
        write_log( "fread PE which_arch() fail\n");
        return FREAD_FAIL;
    }
	/*
     *  controllo se PE e arch
    */
    if( (coff_header.Signature[SIGN_0]==PESIGN_0) && (coff_header.Signature[SIGN_1]==PESIGN_1) && 
        (coff_header.Signature[SIGN_2]==PESIGN_2) && (coff_header.Signature[SIGN_3]==PESIGN_3) ){
        
        if( (magic[MAG_0]==PE32MAG_0) && (magic[MAG_1]==PE32MAG_1) ){
            write_log( "input file PE 32 bit\n");
            return (HDR_ARCH_32 | HDR_PE_FILE);
        }
        if( (magic[MAG_0]==PE64MAG_0) && (magic[MAG_1]==PE64MAG_1) ){
            write_log( "input file PE 64 bit\n");
            return (HDR_ARCH_64 | HDR_PE_FILE);
        }
        write_log( "wrong arch on input file\n");
        return WRONG_ARCH;
    }
    write_log( "input file is not elf or pe\n");
    return NOT_ELF_PE;
}




int read_text_section( hdr_elf_data*  input_data, hdr_section_c* hdr_code ){
    char* sh_str;	/* section-header string-table is also a section. */
    int i; 
    // leggo la section header string table utilizzata per detirminare il nome ( stringa )
	// di ogni sezione. Poi leggo ogni sezione e se il nome è .text (ovvero la sezione che 
	// contiene la maggior parte del codice) ne estraggo il contenuto e lo ritorno.
	if(CS_MODE == CS_MODE_64){
		sh_str = read_section64( input_data->fd, input_data->sh64_tbl[input_data->eh64->e_shstrndx]);
		// cerco dove inizia e la dimenzione di .text ovvero il codice
		for( i=0; i<input_data->eh64->e_shnum ; i++){
			if( strncmp( ( sh_str + input_data->sh64_tbl[i].sh_name) , 
						CODE_SECTION_NAME_ELF, strlen(CODE_SECTION_NAME_ELF)) == 0 ){
				
				hdr_code->CODE = read_section64( input_data->fd, input_data->sh64_tbl[i] );
				hdr_code->section_size = input_data->sh64_tbl[i].sh_size;
				hdr_code->index = i;

				return true;
			}
		}
	}
	if(CS_MODE == CS_MODE_32){
		sh_str = read_section( input_data->fd, input_data->sh32_tbl[input_data->eh32->e_shstrndx]);
		// cerco dove inizia e la dimenzione di .text ovvero il codice
		for( i=0; i<input_data->eh32->e_shnum ; i++){
			if( strncmp( ( sh_str + input_data->sh32_tbl[i].sh_name) , 
						CODE_SECTION_NAME_ELF, strlen(CODE_SECTION_NAME_ELF)) == 0 ){
				
				hdr_code->CODE = read_section( input_data->fd, input_data->sh32_tbl[i] );
				hdr_code->section_size = input_data->sh32_tbl[i].sh_size;
				hdr_code->index = i;
				return true;
			}
		}
	}
    
    return false;
}


int read_pe_text_section( hdr_pe_data*  input_data, hdr_section_c* hdr_code ){
    int i; 
    
	for( i=0; i<input_data->coff_header.NumberOfSections ; i++){
	    write_log( "%d NAME %s \n",i,input_data->sh_tbl[i].Name);
		if( strncmp( input_data->sh_tbl[i].Name , 
					CODE_SECTION_NAME_ELF, strlen(CODE_SECTION_NAME_ELF)) == 0 ){
			
			write_log( "index:%d name:%s size:0x%x at offset %d\n", i, input_data->sh_tbl[i].Name, 
							input_data->sh_tbl[i].SizeOfRawData ,input_data->sh_tbl[i].PointerToRawData );
			hdr_code->CODE = malloc( sizeof(char)*input_data->sh_tbl[i].SizeOfRawData );
            if ( hdr_code->CODE == NULL ){
                write_log("malloc hdr_code->CODE failed\n");
                sleep(2);
                exit(1);
            }
	    	if( fseek(input_data->fp,input_data->sh_tbl[i].PointerToRawData,SEEK_SET) < 0){
		    	write_log("fseek errore\n");
			    return -1;
	    	}
		    if( fread( hdr_code->CODE, 1, input_data->sh_tbl[i].SizeOfRawData, 
						input_data->fp) < input_data->sh_tbl[i].SizeOfRawData ){
				write_log( "fread PE read_pe_text_header fail\n");
				return FREAD_FAIL;
			} 
			hdr_code->section_size = input_data->sh_tbl[i].SizeOfRawData;
			hdr_code->index = i;
			return true;
		}
	}
    return false;
}

