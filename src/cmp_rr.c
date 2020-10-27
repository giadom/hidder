// includiamo tutte le specifiche 
#include "hidder.h"


int cmp_subs( cs_insn* insn, int index, int num_ists, struct hdr_data_message *data, unsigned char* output){
    
    if( insn[index].id != X86_INS_CMP ) return error;
    // dichiaro qualche variabile
    int ret,ret2,i;
    uint8_t bit;
    // declare temp op_str
    char op_str[160];
    strcpy( op_str, insn[index].op_str) ;
    
    
    char * reg1 = strtok( op_str, OPERAND_DELIMITATOR);
    char * reg2 = strtok( NULL, OPERAND_DELIMITATOR);
    
    if( reg1==NULL || reg2==NULL){
        return error; 
    }
    // inizializzo keystone
    ks_engine *ks; // E' l'handle delle keystone API 
    ks_err err;
    size_t ks_count;
    size_t ks_size; // dimensione di encode
    char reverse_instr[ ADDSUB_INSTR_MAX_LEN ];
    unsigned char* ks_output;
    ret2 = flag_reg(&reg2[1]);
    ret = flag_reg(reg1);
    
    if( (ret>=0) && (ret2>=0) ){
        /*
            controllo che la modifica dell'istruzione non cambi i flag.
        */
        if ( strcmp( reg1,&reg2[1] )==0 ){
            return error;
        }
        if( !check_flag( insn, (OF|CF|SF), index, num_ists) ){
            return error;
        }
        /*write_log("0x%"PRIx64": %s %s\t", insn[index].address, insn[index].mnemonic,
                insn[index].op_str);
        for( i=0; i<insn[index].size; i++){
            write_log( "%x ", insn[index].bytes[i]);
        }
        write_log( "\n" );*/
        
        /*
        *   inverto l'istruzione per encodare il bit
        */
        sprintf( reverse_instr, "%s %s, %s", insn[index].mnemonic, &reg2[1], reg1);
        
        // inizializza( architettura, ise, handle)
        if( CS_MODE == CS_MODE_32){
            err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks); 
        }
        if( CS_MODE == CS_MODE_64){
            err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks); 
        }

        if (err != KS_ERR_OK) {
            write_log( "ERROR: failed on ks_open(), quit\n");
            return error;
        }
                 
        // compilo l'alternativa
        if (ks_asm(ks, reverse_instr, 0, &ks_output, &ks_size, &ks_count) != KS_ERR_OK) {
            write_log( "ERROR: ks_asm() failed & count = %lu, error = %u\n",
                    ks_count, ks_errno(ks));

            ks_close(ks);
            return error;
        }else{ 
            /*
            *   se il ks_size ( la lunghezza dell'istruzione macchina sostitutrice )
            *   è maggiore dell'istruzione ovviamente cambieremo la dimensione del file
            *   quindi abortiamo il cambio
            */
            if( ks_size != insn[index].size ){  
                return error;
            }
            // salvo dati solo per fini statistici
            cont_istr.cmp_rr++;

            /*
            *   prendo il bit da encodare, dato che add e sub possono un solo bit
            */
            uint8_t tmp = take_bits( data, 1 );
            
            if( (tmp) && ( flag_reg(reg1)>=flag_reg(&reg2[1]) ) ){
                return BIT_ALREADY_ENCODED;
            }
            if( (!tmp) && ( flag_reg(reg1)<flag_reg(&reg2[1]) ) ){
                return BIT_ALREADY_ENCODED;
            }
   
            /*
            *   nel caso della sostituzione ritorno la funzione da sostituire
            */
            for (i = 0; i < ks_size; i++) {
                output[i] = ks_output[i];
            }
            // close Keystone instance when done
            ks_free(ks_output);
            ks_close(ks);
            return ks_size;
        }
    }else{
            return error;
    } 
}




int cmp_is_subs( cs_insn* insn, int index, int num_ists ){
    
    if( insn[index].id != X86_INS_CMP ) return error;
    // dichiaro qualche variabile
    int ret,ret2,i;
    uint8_t bit;
    // declare temp op_str
    char op_str[160];
    strcpy( op_str, insn[index].op_str) ;
    
    /*
    *   controllo che r/m == r
    */
    char * reg1 = strtok( op_str, OPERAND_DELIMITATOR);
    char * reg2 = strtok(NULL, OPERAND_DELIMITATOR);
    
    if( reg1==NULL || reg2==NULL){
        return error; 
    }
    // inizializzo keystone
    ks_engine *ks; // E' l'handle delle keystone API 
    ks_err err;
    size_t ks_count;
    size_t ks_size; // dimensione di encode
    char reverse_instr[ ADDSUB_INSTR_MAX_LEN ];
    unsigned char* ks_output;
    ret2 = is_reg(&reg2[1]);
    ret = is_reg(reg1);
    if( (ret>=0) && (ret2>=0) ){
        /*
            controllo che la modifica dell'istruzione non cambi i flag.
        */
        if ( strcmp( reg1,&reg2[1] )==0 ){
            return error;
        }
        if( !check_flag( insn, (OF|CF|SF), index, num_ists) ){
            //write_log("NOOOO");
            return error;
        }
        
        /*
        *   inverto l'istruzione per encodare il bit
        */
        sprintf( reverse_instr, "%s %s, %s", insn[index].mnemonic, &reg2[1], reg1);
        
        // inizializza( architettura, ise, handle)
        if( CS_MODE == CS_MODE_32){
            err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks); 
        }
        if( CS_MODE == CS_MODE_64){
            err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks); 
        }

        if (err != KS_ERR_OK) {
            write_log( "ERROR: failed on ks_open(), quit\n");
            return error;
        }
                 
        // compilo l'alternativa
        if (ks_asm(ks, reverse_instr, 0, &ks_output, &ks_size, &ks_count) != KS_ERR_OK) {
            write_log( "ERROR: ks_asm() failed & count = %lu, error = %u\n",
                    ks_count, ks_errno(ks));

            ks_close(ks);
            return error;
        }else{ 
            /*
            *   se il ks_size ( la lunghezza dell'istruzione macchina sostitutrice )
            *   è maggiore dell'istruzione ovviamente cambieremo la dimensione del file
            *   quindi abortiamo il cambio
            */
            if( ks_size != insn[index].size ){  
                return error;
            }
            
            if( flag_reg(reg1)<flag_reg(&reg2[1]) ){
                return 0;
            }else{
                return 1;
            }
            
        }
    }else return error;

}