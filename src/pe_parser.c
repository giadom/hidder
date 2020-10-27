// includiamo tutte le specifiche ds
#include "hidder.h"

int read_pe32_header( struct hdr_pe_data* input_data ){
    int temp=0;
    /* portiamo il file pointer all'inizio del file */
  	if( fseek( input_data->fp, 0, SEEK_SET) != 0 ){
        write_log( "fseek read_pe32_header fail\n");
        return FSEEK_FAIL;
    } 
    /*
     *  leggiamo DOS header che determina il punto di partenza del COFF header
    */
    if( fread( &(input_data->ms_dos), 1, sizeof(ms_dos_stub), input_data->fp) < sizeof(ms_dos_stub) ){
        write_log( "fread ms_dos PE read_pe32_header fail\n");
        return FREAD_FAIL;
    }
    // stampo offset signature
    //write_log( "offset coff %x dim %x\n", input_data->ms_dos.offset_signature,sizeof(ms_dos_stub));
    
    
    
    /* portiamo il file pointer all'inizio del COFF header */
  	if( fseek( input_data->fp, input_data->ms_dos.offset_signature, SEEK_SET) != 0 ){
        write_log( "fseek read_pe32_header fail\n");
        return FSEEK_FAIL;
    } 
	/*
     *  leggiamo COFF header
    */
    if( fread( &(input_data->coff_header), 1, sizeof(coff_file_header), 
                input_data->fp) < sizeof(coff_file_header) ){
        write_log( "fread coff header PE read_pe32_header fail\n");
        return FREAD_FAIL;
    }
    // stampo COFF header
    //write_log( "signature %02x%02x dim %d\n", input_data->coff_header.Signature[0],input_data->coff_header.Signature[1] , sizeof(coff_file_header));
    //write_log( "Machine %x\nNunmber Section %x\ndim %d\n",input_data->coff_header.Machine,
    // input_data->coff_header.NumberOfSections ,input_data->coff_header.SizeOfOptionalHeader );
    

    
    /*
     *  leggiamo standard field
    */
    if( fread(  input_data->std_field_32, 1, sizeof(oh32_standard_field), 
                input_data->fp) < sizeof(oh32_standard_field) ){
        write_log( "fread std_field PE read_pe32_header fail\n");
        return FREAD_FAIL;
    }
    

    /*
     *  leggiamo windows specific field
    */
    if( fread(  input_data->win_specific_32, 1, sizeof(oh32_windows_specific), 
                input_data->fp) < sizeof(oh32_windows_specific) ){
        write_log( "fread win spec field PE read_pe32_header fail\n");
        return FREAD_FAIL;
    }


    /*
     *  leggiamo tutte le entry di data directory
    */
    if (input_data->win_specific_32->NumberOfRvaAndSizes > DATA_DIR_NUMBER) {
        input_data->win_specific_32->NumberOfRvaAndSizes = DATA_DIR_NUMBER;
    }
    
    temp = ( sizeof(data_directory)*input_data->win_specific_32->NumberOfRvaAndSizes );
    input_data->dt_dir = malloc(temp);
    if ( input_data->dt_dir == NULL ){
        write_log("malloc input_data->dt_dir failed\n");
        sleep(2);
        exit(1);
    }
    
    if( fread(  input_data->dt_dir, 1, temp, input_data->fp) < temp ){
        write_log( "fread data directory PE read_pe32_header fail\n");
        return FREAD_FAIL;
    }
    

    /*
     *  leggiamo tutte le entry di section header
    */
    temp = ( sizeof(image_section_header)*input_data->coff_header.NumberOfSections );
    input_data->sh_tbl = malloc( temp );
    if ( input_data->sh_tbl == NULL ){
        write_log("malloc input_data->sh_tbl failed\n");
        sleep(2);
        exit(1);
    }
    
    if( fread( input_data->sh_tbl, 1, temp, input_data->fp) < temp ){
        write_log( "fread section header PE read_pe32_header fail\n");
        return FREAD_FAIL;
    }
}


int read_pe64_header( struct hdr_pe_data* input_data ){
    int temp=0;
    /* portiamo il file pointer all'inizio del file */
  	if( fseek( input_data->fp, 0, SEEK_SET) != 0 ){
        write_log( "fseek read_pe64_header fail\n");
        return FSEEK_FAIL;
    } 
    /*
     *  leggiamo DOS header che determina il punto di partenza del COFF header
    */
    if( fread( &(input_data->ms_dos), 1, sizeof(ms_dos_stub), input_data->fp) < sizeof(ms_dos_stub) ){
        write_log( "fread ms_dos PE read_pe64_header fail\n");
        return FREAD_FAIL;
    }
    
    
    /* portiamo il file pointer all'inizio del COFF header */
  	if( fseek( input_data->fp, input_data->ms_dos.offset_signature, SEEK_SET) != 0 ){
        write_log( "fseek read_pe64_header fail\n");
        return FSEEK_FAIL;
    } 
	/*
     *  leggiamo COFF header
    */
    if( fread( &(input_data->coff_header), 1, sizeof(coff_file_header), 
                input_data->fp) < sizeof(coff_file_header) ){
        write_log( "fread coff header PE read_pe64_header fail\n");
        return FREAD_FAIL;
    }

    
    /*
     *  leggiamo standard field
    */
    if( fread(  input_data->std_field_64, 1, sizeof(oh64_standard_field), 
                input_data->fp) < sizeof(oh64_standard_field) ){
        write_log( "fread std_field PE read_pe64_header fail\n");
        return FREAD_FAIL;
    }

    /*
     *  leggiamo windows specific field
    */
    if( fread(  input_data->win_specific_64, 1, sizeof(oh64_windows_specific), 
                input_data->fp) < sizeof(oh64_windows_specific) ){
        write_log( "fread win spec field PE read_pe64_header fail\n");
        return FREAD_FAIL;
    }
    

    /*
     *  leggiamo tutte le entry di data directory
    */
    if (input_data->win_specific_64->NumberOfRvaAndSizes > DATA_DIR_NUMBER) {
        input_data->win_specific_64->NumberOfRvaAndSizes = DATA_DIR_NUMBER;
    }
    
    temp = ( sizeof(data_directory)*input_data->win_specific_64->NumberOfRvaAndSizes );
    input_data->dt_dir = malloc(temp);
    if ( input_data->dt_dir == NULL ){
        write_log("malloc input_data->dt_dir failed\n");
        sleep(2);
        exit(1);
    }
    
    if( fread(  input_data->dt_dir, 1, temp, input_data->fp) < temp ){
        write_log( "fread data directory PE read_pe64_header fail\n");
        return FREAD_FAIL;
    }
    /*for( temp=DIR_EXPORT; temp<=DIR_RESERVED; temp++ ){
        write_log( "RVA: 0x%x size:0x%x\n",input_data->dt_dir[temp].VirtualAddress,input_data->dt_dir[temp].Size );
    }*/

    /*
     *  leggiamo tutte le entry di section header
    */
    temp = ( sizeof(image_section_header)*input_data->coff_header.NumberOfSections );
    input_data->sh_tbl = malloc( temp );
    if ( input_data->sh_tbl == NULL ){
        write_log("malloc input_data->sh_tbl failed\n");
        sleep(2);
        exit(1);
    }
    
    if( fread( input_data->sh_tbl, 1, temp, input_data->fp) < temp ){
        write_log( "fread section header PE read_pe64_header fail\n");
        return FREAD_FAIL;
    }


}


int stampa( struct optional_header_64_windows_specific *win){
    write_log( "\nwin_specific size %d\n",  sizeof(oh64_windows_specific) );
    write_log( "Image Base 0x%x\n",  win->ImageBase );
    write_log( "Section Alignment 0x%x\n",  win->SectionAlignment );
    write_log( "file allignment 0x%x\n",  win->FileAlignment );
    write_log( "maj os version 0x%x\n",  win->MajorOperatingSystemVersion );
    write_log( "min os version 0x%x\n",  win->MinorOperatingSystemVersion );
    write_log( "maj im version 0x%x\n",  win->MajorImageVersion );
    write_log( "min im version 0x%x\n",  win->MinorImageVersion );
    write_log( "maj sub 0x%x\n",  win->MajorSubsystemVersion );
    write_log( "min sub 0x%x\n",  win->MinorSubsystemVersion );
    write_log( "win32 version 0x%x\n",  win->Win32VersionValue );
    write_log( "Size of Image 0x%x\n",  win->SizeOfImage );
    write_log( "Size of Header 0x%x\n",  win->SizeOfHeaders );
    write_log( "checksum 0x%x\n",  win->CheckSum );
    write_log( "subsystem 0x%x\n",  win->Subsystem );
    write_log( "dll characteristic 0x%x\n",  win->DllCharacteristics );
    write_log( "stack reserve 0x%x\n",  win->SizeOfStackReserve );
    write_log( "stack commit 0x%x\n",  win->SizeOfStackCommit );
    write_log( "heap reserve 0x%x\n",  win->SizeOfHeapReserve );
    write_log( "heap commit 0x%x\n",  win->SizeOfHeapCommit );
    write_log( "loader flags 0x%x\n",  win->LoaderFlags );
    write_log( "rva num 0x%x\n",  win->NumberOfRvaAndSizes );
    write_log( "\n\n");
}