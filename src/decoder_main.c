// header libreria
#include "hidder.h"


int decoder_main(int argc, char *argv[])
{
    if(argc != 3){
        write_log("Formato errato prova:\n./hidder [path file da decodificare] [path file output]\n");
        exit(1);
    }
    // variabili multi uso per return cicli e temporanei
    int i,j,ret;
    unsigned char temp;

    /*
        inizializzo struttura base
    */
    hdr_data* hdr_data = malloc( sizeof(struct hdr_data_message) );
    if(hdr_data == NULL)
    {
        write_log("hdr_data malloc fail\n");
        exit(1);
    }

    /*
        get password for the file and hash it
    */
    hdr_data->password = getpass("Enter a password: ");
    
    pass_to_digest(hdr_data);
    
    get_iv(hdr_data);

    // verranno utilizzati per decriptare questa volta
    hdr_data->byte_encoded_size=0; 
    hdr_data->bit_encoded=0;
    for (i = 0; i < INT_BYTES_LEN; i++)
    {
        hdr_data->crypted_plaintext_len[i]=0;
    }
    
    FILE *f_output = NULL;
    f_output = fopen( argv[2] ,"wb");
    if( (f_output == NULL) )
    {
        write_log("Error on opening input %s\n",strerror(errno));
        exit(1);
    }
    hdr_data->f_output=f_output;
    /*
     *  Apriamo il file eseguibile e determiniamo l'architettura
     *  Creo il file di output o se gia esiste lo "resetto"
    */
    FILE *f_input = NULL;
    
    // x86  /home/osboxes/Desktop/ctf/binary-exploitation-intro-master/home/4.spiderpork/spiderpork
    // x64  /home/osboxes/Desktop/ctf/binary-exploitation-intro-master/home/2. hi/hi
    f_input = fopen( argv[1] ,"rb+");
    if( (f_input == NULL) )
    {
        write_log("Error on opening input %s\n",strerror(errno));
        exit(1);
    }
    if ( ( ret = which_arch(f_input) ) < 0 ){
        exit(1);
    }
    if( (ret & HDR_ELF_FILE) == HDR_ELF_FILE ){
        decoder_elf_main(    (ret&(HDR_ARCH_32|HDR_ARCH_64)) , 
                            f_input, hdr_data);
    }
    if( (ret & HDR_PE_FILE) == HDR_PE_FILE ){
        decoder_pe_main(    (ret&(HDR_ARCH_32|HDR_ARCH_64)) , 
                            f_input, hdr_data);
    }
    
    
    return 0;
}

