// header libreria
#include "hidder.h"

_Bool e_opt_dec=0;
char *p_opt_dec=NULL;

int decoder_main(int argc, char *argv[])
{
    // variabili multi uso per return cicli e temporanei
    int i,j,ret;
    unsigned char temp;
    
    // Anche se i file li usero` dopo, li incomincio ad aprire visto che devo agire sulle eventuali opzioni
    FILE *f_output = NULL;
    FILE *f_input = NULL;
    if(argc!=3 && 4!=argc)
    {
formato_errato:
        write_log(
                  "Formato errato prova:\n./decoder path_file_da_decodificare path_file_output\n"\
                  "Oppure:\n./decoder -e [-p] path_file_da_decodificare\n"
                 );
        exit(EXIT_FAILURE);
    }
    else
    {
        /*
            Usufruisco di getopt (definito in unistd.h) per estrapolare le opzioni. unistd.h e` gia` importato in hidder.h.
            https://www.gnu.org/software/libc/manual/html_node/Using-Getopt.html#Using-Getopt
        */
        opterr=0; // Non voglio usufruire del messaggio di errore predefinito di getopt
        while( -1 != (ret=getopt(argc,argv,"ep")) )
        {
            switch(ret)
            {
                case 'e':
                    e_opt_dec=1;
                    break;
                case 'p':
                    p_opt_dec=(char*)'p'; // Ci metto un valore temporaneo (in verita` dovra` puntare ad altro)
                    break;
                default:
                    break;
            }
        }
                            //printf("optind:%d\nf_input:%s\nf_output:%s\n",optind,argv[optind],argv[optind+1]);
        if(0==e_opt_dec && NULL==p_opt_dec)
        {
            f_input = fopen( argv[1] ,"rb+");
            f_output = fopen( argv[2] ,"wb");
        }
        else
        {
            // optind e` l'indice della prima non-opzione. getopt riarrangia argv mettendo in fondo le non-opzioni.
            // Se e` presente l'opzione -e, non bisogna trascrivere alcun messaggio su un file ed f_output rimane a NULL.
            if(1==e_opt_dec)
                f_input = fopen( argv[optind] ,"rb+");
            // Se ho fornito l'opzione -p, p_opt_dec puntera` al nome del contenitore da eseguire
            if(NULL!=p_opt_dec)
            {
                // -p deve lavorare in coppia con -e.
                if(0==e_opt_dec)
                    goto formato_errato;
                p_opt_dec=argv[optind];
            }
        }
    }
    

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
    
    if( f_output==NULL && 0==e_opt_dec ) // Se non c'e` -e allora ci deve essere il file di output
    {
        write_log("Error on opening input %s\n",strerror(errno));
        exit(1);
    }
    hdr_data->f_output=f_output;
    
    // x86  /home/osboxes/Desktop/ctf/binary-exploitation-intro-master/home/4.spiderpork/spiderpork
    // x64  /home/osboxes/Desktop/ctf/binary-exploitation-intro-master/home/2. hi/hi
    if( (f_input == NULL) )
    {
        write_log("Error on opening input %s\n",strerror(errno));
        exit(1);
    }
    // Determiniamo l'architettura
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

