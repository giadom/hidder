
// header libreria 
#include "hidder.h"

void init_logs_var(){
    cont_istr.add_s=0;
    cont_istr.sub=0;
    cont_istr.adc=0;
    cont_istr.add=0;
    cont_istr.and=0;
    cont_istr.cmp=0;
    cont_istr.mov=0;
    cont_istr.or=0;
    cont_istr.sbb=0;
    cont_istr.test=0;
    cont_istr.sub_x=0;
    cont_istr.xor=0;
    cont_istr.size=0;
    cont_istr.test1=0;
    cont_istr.or1=0;
    cont_istr.and1=0;
    cont_istr.add1=0;
    cont_istr.sub1=0;
    cont_istr.xor1=0;
    cont_istr.cmp1=0;
    cont_istr.big8=0;
    cont_istr.big16=0;
    cont_istr.big32=0;
    cont_istr.big64=0;
    cont_istr.cmp_rr=0;

}

void print_logs_value(){

    write_log( "+=======RECAP_OFFUSCAMENTO========+\n");
    write_log( "DIMENSIONE CODICE: circa %d Bytes\n", cont_istr.size );

    write_log( "+===SOSTITUZIONE_ISTR. CONSECUTIVE circa %d Bytes\n",(cont_istr.big8*7 +
                        cont_istr.big16*15 + cont_istr.big32*31 + cont_istr.big64*63)/8 );
    write_log( " 8=%d \n16=%d \n32=%d \n64=%d\n", cont_istr.big8,
                        cont_istr.big16, cont_istr.big32, cont_istr.big64 );

    write_log( "+=======SOSTITUZIONE_ADD_SUB circa %d Bytes\n", (cont_istr.sub + cont_istr.add_s)/8 );            
    write_log( "add %d\n", cont_istr.add_s );
    write_log( "sub %d\n",cont_istr.sub);

    write_log( "+=======SOSTITUZIONE_FORMATI circa %d Bytes\n",
                (cont_istr.adc+cont_istr.add+cont_istr.cmp+cont_istr.mov+cont_istr.sbb)/8 );
    write_log( "adc %d\n",cont_istr.adc);
    write_log( "add %d\n",cont_istr.add);
    write_log( "cmp %d\n",cont_istr.cmp);
    write_log( "mov %d\n",cont_istr.mov);
    write_log( "sbb %d\n",cont_istr.sbb);

    write_log( "+=======SOSTITUZIONE_TOA circa %d Bytes\n",(((cont_istr.test+cont_istr.or+cont_istr.and)*(2))/8) );      
    write_log( "test %d\n",cont_istr.test);
    write_log( "or   %d\n",cont_istr.or);
    write_log( "and  %d\n",cont_istr.and);

    write_log( "+=======SOSTITUZIONE_TOA circa %d Bytes\n",(((cont_istr.xor+cont_istr.sub_x)*(2))/8) ); 
    write_log( "sub %d\n",cont_istr.sub_x);
    write_log( "xor %d\n",cont_istr.xor);

    write_log( "+=======SOSTITUZIONE_TOACXS circa %d Bytes\n", (int)((cont_istr.test1 + cont_istr.or1
             + cont_istr.and1 + cont_istr.add1 + cont_istr.sub1 + cont_istr.xor1 + cont_istr.cmp1)*(2.8))/8 );

    write_log( "test %d\n",cont_istr.test1);
    write_log( "or   %d\n",cont_istr.or1);
    write_log( "and  %d\n",cont_istr.and1);
    write_log( "add  %d\n",cont_istr.add1);
    write_log( "sub  %d\n",cont_istr.sub1);
    write_log( "xor  %d\n",cont_istr.xor1);
    write_log( "cmp  %d\n",cont_istr.cmp1);

    write_log( "+=======SOSTITUZIONE_CMP_RR circa %d Bytes\n",cont_istr.cmp_rr/8);
    write_log( "cmp_rr %d\n",cont_istr.cmp_rr);

}


int hidder_main(int argc, char *argv[])
{   
    init_logs_var();

    if(argc != 4){
        write_log("Formato errato prova:\n./hidder [path file eseguibile] [file output] [file messaggio]\n");
        exit(1);
    }
    
    // variabili multi uso per return cicli e temporanei
    int i,j,ret;
    unsigned char temp;

    /*
    *    inizializzo struttura base
    */
    hdr_data* hdr_data = malloc( sizeof(struct hdr_data_message) );
    if(hdr_data == NULL)
    {
        write_log("hdr_data malloc fail\n");
        exit(1);
    }
    
    /*
    *   get password funzione sicura per inserimento password,
    *   utilizzo la funzione SHA-256 e stampo il digest
    */
    hdr_data->password = getpass("Enter a password: ");
    
    pass_to_digest(hdr_data);
    
    /*
    *   leggo il plaintext e lo cripto
    */
    if( !( read_plaintext( argv[3], hdr_data) ) ){
        write_log("Error read_plaintext\n");
        exit(1);
    } 
    
    encrypt_plaintext( hdr_data );
    hdr_data->bit_encoded=0;
    hdr_data->byte_encoded_size=0;
    free(hdr_data->plaintext);


    /*
    *   Apriamo il file eseguibile e determiniamo l'architettura
    *   Creo il file di output o se gia esiste lo "resetto"
    */
    FILE *f_input = NULL;
    FILE *f_output = NULL;

    f_output = fopen( argv[2] ,"wb");
    f_input = fopen( argv[1] ,"rb+");
    
    if( (f_input == NULL) || (f_output == NULL))
    {
        write_log("Error on opening input/output: %s\n", strerror(errno));
        exit(1);
    }
    /* 
    *   Determiniamo FORMATO e ARCHITETTURA 
    * */
    if ( ( ret = which_arch(f_input) ) < 0 ){
        exit(1);
    }
    
    if( (ret & HDR_ELF_FILE) == HDR_ELF_FILE ){
        
        hidder_elf_main(    (ret&(HDR_ARCH_32|HDR_ARCH_64)) , 
                            f_input, f_output, hdr_data);
    }
    if( (ret & HDR_PE_FILE) == HDR_PE_FILE ){
        
        hidder_pe_main(    (ret&(HDR_ARCH_32|HDR_ARCH_64)) , 
                            f_input, f_output, hdr_data);
    }

    print_logs_value();
    
    fclose(f_input);
    fclose(f_output);
    free_hdr_data(hdr_data);
    free_global();
    return 0;
}
