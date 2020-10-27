/*
*   header per i set di istruzioni
*/
#include "hidder.h"

/* 
*   inverte un'istruzione add/sub con il suo reciproco, es. ADD rax, 50 => SUB rax, -50
*   ritorna in caso di riuscita il numero di bytes dell'opcode e in ks_output l'opcode del reciproco. 
*   ritorna false ovvero 0 in caso di BIT_ALREADY_ENCODED
*   ritorna error ovvero -1 in caso di qualche errore e stampa l'errore prima di uscire
*/
int addsub_imm_s( cs_insn* insn, int index, int num_ists, struct hdr_data_message *data, unsigned char* output){
    
    char reverse_instr[ ADDSUB_INSTR_MAX_LEN ];
    // creo l'alternativa dell'istruzione add/sub
    if( insn[index].id == X86_INS_ADD ){
        strcpy( reverse_instr, "sub " );
    }else{
        if( insn[index].id == X86_INS_SUB ){
            strcpy( reverse_instr, "add " );
        }else{
            return error;
        }
    }
    // inizializzo keystone
    ks_engine *ks; // E' l'handle delle keystone API 
    ks_err err;
    size_t ks_count;
    size_t ks_size; // dimensione di encode

    int i,op_reg_index;
    unsigned char* ks_output;

    // declare temp op_str
    char op_str[160];
    strcpy( op_str, insn[index].op_str) ;

    /*
    *   controllo che source sia un imm8/16/31/64
    */
    char * token = strtok( op_str, OPERAND_DELIMITATOR);
    char * resto;
    //creo temporaneamente il flag del registro, se l'istruzione sarà valida lo salvo globalmente
    op_reg_index = flag_reg(token);
    unsigned long reg_flag_temp = (op_reg_index<0)?0:((unsigned long)1 << op_reg_index);

    strcat( reverse_instr, token);
    token = strtok(NULL, OPERAND_DELIMITATOR);
    int num = (int)strtol(token, &resto, 16);
    // se num=0 c'è stato un errore, mentre se resto è != da una stringa vuota allora probabilmente 
    // ha letto un registro eax.. ha tradotto ea in num e messo x in resto --> errore 
    if( (num == 0) || ( *resto != '\x0' ) ){
        return error;
    }else{
        /*
            controllo che la modifica dell'istruzione non cambi i flag.
        */
        if( !check_flag( insn, (OF|CF), index, num_ists) ){
            return error;
        }
        
        /*
        *   inverto l'istruzione per encodare il bit
        */
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

        num = num * (-1);
        sprintf( reverse_instr, "%s, %d", reverse_instr, num);
                 
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
                ks_free(ks_output);
                ks_close(ks);
                return error;
            }
            // salvo dati solo per fini statistici
            if( insn[index].id == X86_INS_ADD) cont_istr.add_s++;
            if( insn[index].id == X86_INS_SUB) cont_istr.sub++;

            /*
            *   se la lunghezza dell'istruzione macchina è minore di quella attuale
            *   potremo autofillare con le nop per non modificare il size del file eseguibile
            */
            if( ks_size < insn[index].size ){
                ks_free(ks_output);
                ks_close(ks);
                return error;
            }

            /*
            *   l'operazione ha superato tutti i requisiti, salvo il flag
            */
            if( registri.reg_flag & reg_flag_temp){
                
                switch( (op_reg_index / 16) ){
                    case REG_8_BIT:
                        cont_istr.big8++;
                        break;
                    case REG_16_BIT:
                        cont_istr.big16++;
                        break;
                    case REG_32_BIT:
                        cont_istr.big32++;
                        break;
                    case REG_64_BIT:
                        cont_istr.big64++;
                        break;
                    default:
                        write_log( "No sense switch reg flags");
                        sleep(10);
                        break;
                }

                registri.reg_flag &= ~reg_flag_temp;
            }else{
                
                registri.reg_flag |= reg_flag_temp;
            }

            /*
            *   prendo il bit da encodare, dato che add e sub possono un solo bit
            */
            
            uint8_t tmp = take_bits( data, 1 );
            
            /*
            *   usiamo add per encodare 0, sub per encodare 1. 
            *   Controllo che non sia gia l'istruzione corretta.
            */
            
            if( (tmp && ( strcmp( insn[index].mnemonic, "sub" )==0 )) || ( (!tmp) && ( strcmp( insn[index].mnemonic, "add" )==0 )) ){
                ks_free(ks_output);
                ks_close(ks);
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
    }
}


int addsub_imm_is_s( cs_insn* insn, int index, int num_ists){
  
    // inizializzo keystone
    ks_engine *ks; // E' l'handle delle keystone API 
    ks_err err;
    size_t ks_count;
    size_t ks_size; // dimensione di encode
    unsigned char* ks_output;
    char reverse_instr[ ADDSUB_INSTR_MAX_LEN ];
    // declare temp op_str
    char op_str[160];
    strcpy( op_str, insn[index].op_str) ;

    int i;
    // creo l'alternativa dell'istruzione add/sub
    if( insn[index].id == X86_INS_ADD ){
        strcpy( reverse_instr, "sub " );
    }else{
        if( insn[index].id == X86_INS_SUB ){
            strcpy( reverse_instr, "add " );
        }else{
            return error;
        }
    }
    /*
    *   controllo che source sia un imm8/16/31/64
    */
    char * token = strtok( op_str, OPERAND_DELIMITATOR);
    char * resto;
    strcat( reverse_instr, token);
    token = strtok(NULL, OPERAND_DELIMITATOR);
    int num = (int)strtol(token, &resto, 16);
    
    // se num=0 c'è stato un errore, mentre se resto è != da una stringa vuota allora probabilmente 
    // ha letto un registro eax.. ha tradotto ea in num e messo x in resto --> errore 
    if( (num == 0) || ( *resto != '\x0' ) ){
        return error;
    }else{
        /*
            controllo che la modifica dell'istruzione non cambi i flag.
        */
        if( !check_flag( insn, (OF|CF), index, num_ists) ){
            return error;
        }
        
        /*
        *   inverto l'istruzione per encodare il bit
        */
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

        num = num * (-1);
        sprintf( reverse_instr, "%s, %d", reverse_instr, num);
                
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
            if( ks_size > insn[index].size ){
                return error;
            }
            /*
            *   se la lunghezza dell'istruzione macchina è minore di quella attuale
            *   potremo autofillare con le nop per non modificare il size del file eseguibile
            */
            if( ks_size < insn[index].size ){
                return error;
            } 
            // close Keystone instance when done
            ks_free(ks_output);
            ks_close(ks);
            /*
            *   a questo punto l'insn è valida quindi ha encodato 0 se add oppure 1 se sub
            */
            if( insn[index].id == X86_INS_ADD ){
                return 0;
            }
            if( insn[index].id == X86_INS_SUB ){
                return 1;
            }
        }
    }
}
