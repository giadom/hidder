#include "hidder.h"

/*
*   struct costanti per le toa/toasx istruzioni
*/
struct table toasxc8_table[] =
{
    { { '\xA8', '\xff' }, NF, "test al, -1" },
    { { '\x0C', '\x00' }, NF, "or   al,  0" },
    { { '\x24', '\xff' }, NF, "and  al, -1" },
    { { '\x04', '\x00' }, NF, "add  al,  0" },
    { { '\x2C', '\x00' }, NF, "sub  al,  0" },
    { { '\x34', '\x00' }, NF, "xor  al,  0" },
    { { '\x3C', '\x00' }, NF, "cmp  al,  0" },
};

struct table toasxc16_table[] =
{
    { { '\xf6', '\xc4', '\xff' },  NF, "test ah, -1" },
    { { '\x80', '\xcc', '\x00' },  NF, "or   ah,  0" },
    { { '\x80', '\xe4', '\xff' },  NF, "and  ah, -1" },
    { { '\x80', '\xc4', '\x00' },  NF, "add  ah,  0" },
    { { '\x80', '\xec', '\x00' },  NF, "sub  ah,  0" },
    { { '\x80', '\xf4', '\x00' },  NF, "xor  ah,  0" },
    { { '\x80', '\xfc', '\x00' },  NF, "cmp  ah,  0" },
};

struct table toasxc32_table[] =
{
    { { '\x83', '\xc8', '\x00' },  NF, "or   eax,  0" },
    { { '\x83', '\xe0', '\xff' },  NF, "and  eax, -1" },
    { { '\x83', '\xc0', '\x00' },  NF, "add  eax,  0" },
    { { '\x83', '\xe8', '\x00' },  NF, "sub  eax,  0" },
    { { '\x83', '\xf0', '\x00' },  NF, "xor  eax,  0" },
    { { '\x83', '\xf8', '\x00' },  NF, "cmp  eax,  0" },
};

struct table toasxc64_table[] =
{
    { { '\x48', '\x83', '\xc8', '\x00' },  NF, "or   rax,  0" },
    { { '\x48', '\x83', '\xe0', '\xff' },  NF, "and  rax, -1" },
    { { '\x48', '\x83', '\xc0', '\x00' },  NF, "add  rax,  0" },
    { { '\x48', '\x83', '\xe8', '\x00' },  NF, "sub  rax,  0" },
    { { '\x48', '\x83', '\xf0', '\x00' },  NF, "xor  rax,  0" },
    { { '\x48', '\x83', '\xf8', '\x00' },  NF, "cmp  rax,  0" },
};

/*
*   struct costanti per i primi 8 registri RAX...ESP
*/
struct table toa_8_table[] =
{   
    { {'\x20'}, NF, "and  r/m8 , r8"   },
    { {'\x84'}, NF, "test r/m8 , r8"   },
    { {'\x08'}, NF, "or   r/m8 , r8"   },
    { {'\x22'}, NF, "and  r8   , r/m8" },
    { {'\x0A'}, NF, "or   r8   , r/m8" },
};
struct table toa_16_table[] =
{   
    { {'\x66','\x21'}, NF, "and  r/m16 , r16"   },
    { {'\x66','\x85'}, NF, "test r/m16 , r16"   },
    { {'\x66','\x09'}, NF, "or   r/m16 , r16"   },
    { {'\x66','\x23'}, NF, "and  r16   , r/m16" },
    { {'\x66','\x0B'}, NF, "or   r16   , r/m16" },
};
struct table toa_32_table[] =
{   
    { {'\x21'}, NF, "and  r/m32 , r32"   },
    { {'\x85'}, NF, "test r/m32 , r32"   },
    { {'\x09'}, NF, "or   r/m32 , r32"   },
    { {'\x23'}, NF, "and  r32   , r/m32" },
    { {'\x0B'}, NF, "or   r32   , r/m32" },
};
struct table toa_64_table[] =
{   
    { {'\x48','\x21'}, NF, "and  r/m64 , r64"   },
    { {'\x48','\x85'}, NF, "test r/m64 , r64"   },
    { {'\x48','\x09'}, NF, "or   r/m64 , r64"   },
    { {'\x48','\x23'}, NF, "and  r64   , r/m64" },
    { {'\x48','\x0B'}, NF, "or   r64   , r/m64" },
};


struct insn_sets eq_insn_sets[] = {
    { 7, 2, toasxc8_table },
    { 7, 3, toasxc16_table },
    { 6, 3, toasxc32_table },
    { 6, 4, toasxc64_table },
    { 0, 0, NULL}
};

/*
*   In questa sostituzione, utilizziamo istruzioni con lo stesso registro,
*   sia come source che destinazione. 
*   ES  ADD r/m, r => ADD r, r/m; se utiliziamo come r/m un registro, precisamente lo stesso
*   usato da r, abbiamo 2 istruzioni equivalenti in tutto, dai flag al funzionamento.

*   Possiamo anche utilizzare l'insieme sia 8/32/64 bit, 
*    "test r/m8 , r8"
*    "or   r/m8 , r8"
*    "or   r8   , r/m8"
*    "and  r/m8 , r8"
*    "and  r8   , r/m8"
*   questo insieme utilizzando lo stesso registro abbiamo che; i flag sono affetti allo stesso 
*   modo in ogni istruzione, or/and modificano la destinazione, ma essendo su se stessi il risultato
*   lascia invariato il valore interno e pertando hanno lo stesso effetto di un'istruzione test.

*   Pertanto abbiamo bisogno di solamente l'istruzione controllata 
*   ritorna -1 se non è sostituibile, 0 se è sostituibile e gia l'istruzione corretta
*   altrimenti mette i byte da sostituire in output e la dimensione come return.
*/
int toa_subs( cs_insn* insn, int index, int num_ists, struct hdr_data_message *data, unsigned char* output ){
    
    if( (insn[index].id != X86_INS_AND) && (insn[index].id != X86_INS_OR) && (insn[index].id != X86_INS_TEST) ){
        return error;
    }
    // declare temp op_str
    char op_str[160];
    strcpy( op_str, insn[index].op_str) ;
    
    /*
    *   controllo che r/m == r
    */
    char * reg1 = strtok( op_str, OPERAND_DELIMITATOR);
    char * reg2 = strtok( NULL, OPERAND_DELIMITATOR);
    int ret,i;
    uint8_t bit;
    if( reg1 == NULL || reg2==NULL){
        return error;
    }
    ret = is_reg(reg1);
    if( ( strcmp( reg1, &reg2[1] )==0 ) && ( ret>=0) ){

        if( insn[index].id == X86_INS_TEST) cont_istr.test++;
        if( insn[index].id == X86_INS_OR) cont_istr.or++;
        if( insn[index].id == X86_INS_AND) cont_istr.and++;
        
        switch(ret){
            case REG_8_BIT:
            
                bit = take_bits( data, 2 );
                
                if( insn[index].bytes[0] == '\x40' ){
                    output[0] = '\x40';
                    output[1] = toa_8_table[bit].opcode[0];
                    return 2;
                }else{
                    output[0] = toa_8_table[bit].opcode[0];
                    return 1;
                }
                
            case REG_16_BIT:
            
                bit = take_bits( data, 2 );
                strncpy(output, toa_16_table[bit].opcode, 2);
                return 2;
            case REG_32_BIT:
            
                bit = take_bits( data, 2 );
                output[0] = toa_32_table[bit].opcode[0];
                return 1;
            case REG_64_BIT:
            
                bit = take_bits( data, 2 );
                strncpy(output, toa_64_table[bit].opcode, 2);
                return 2;

            case (REG_8_BIT | REG_R_TYPE):
                
                bit = take_bits( data, 2 );
                output[0] = R_REGS_PREFIX;
                output[1] = toa_8_table[bit].opcode[0];
                return 2;
            case (REG_16_BIT | REG_R_TYPE):
            
                bit = take_bits( data, 2 );
                output[0] = toa_16_table[bit].opcode[0];
                output[1] = R_REGS_PREFIX;
                output[2] = toa_16_table[bit].opcode[1];
                return 3;
            case (REG_R_TYPE | REG_32_BIT):
            
                bit = take_bits( data, 2 );
                output[0] = R_REGS_PREFIX;
                output[1] = toa_32_table[bit].opcode[0];
                return 2;
            case (REG_64_BIT | REG_R_TYPE ):
            
                bit = take_bits( data, 2 );
                output[0] = R_64_BIT_REGS_PREFIX;
                output[1] = toa_64_table[bit].opcode[1];
                return 2;
            default:
                write_log("Qualcosa è andato storto %s %s,%s is_reg()=%d\n",insn[index].mnemonic,reg1, &reg2[1],ret);
                return error;
        }
    }
    return error;
}





/*
*   controlla che l'istruzione sia effettivamente una degli insiemi toa,
*   e ne ritorna l'indice corrispondere (utile per ricostruire il messaggio)
*/
int toa_is_subs( cs_insn insn ){
    if( insn.id != X86_INS_AND && insn.id != X86_INS_OR && insn.id != X86_INS_TEST ){
        return error;
    }
    // declare temp op_str
    char op_str[160];
    strcpy( op_str, insn.op_str) ;
    
    /*
    *   controllo che r/m == r
    */
    char * reg1 = strtok( op_str, OPERAND_DELIMITATOR);
    char * reg2;
    int ret,i;
    uint8_t bit;
    reg2 = strtok(NULL, OPERAND_DELIMITATOR);
    if( reg1 == NULL || reg2==NULL){
        return error;
    }
    if( ( strcmp( reg1, &reg2[1] )==0 ) && ( (ret = is_reg(reg1)) >=0 ) ){
        
        switch(ret){
            case REG_8_BIT:
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( insn.bytes[0] == toa_8_table[i].opcode[0] ){
                        return i;
                    }
                }
                
            case REG_16_BIT:
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( insn.bytes[1] == toa_16_table[i].opcode[1] ){
                        return i;
                    }
                }
            case REG_32_BIT:
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( insn.bytes[0] == toa_32_table[i].opcode[0] ){
                        return i;
                    }
                }
            case REG_64_BIT:
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( insn.bytes[1] == toa_64_table[i].opcode[1] ){
                        return i;
                    }
                }

            case (REG_8_BIT | REG_R_TYPE):
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( insn.bytes[1] == toa_8_table[i].opcode[0] ){
                        return i;
                    }
                }
            case (REG_16_BIT | REG_R_TYPE):
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( insn.bytes[2] == toa_16_table[i].opcode[1] ){
                        return i;
                    }
                }
            case (REG_R_TYPE | REG_32_BIT):
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( insn.bytes[1] == toa_32_table[i].opcode[0] ){
                        return i;
                    }
                }
            case (REG_64_BIT | REG_R_TYPE ):
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( insn.bytes[1] == toa_64_table[i].opcode[1] ){
                        return i;
                    }
                }
            default:
                write_log("Qualcosa è andato storto %s %s,%s is_reg()=%d\n",insn.mnemonic,reg1, &reg2[1],ret);
                return error;
        }
    }
    return error;
}




/*
*   controllo se matcha con toasxcN_table e ritorno l'indice, setto bits 
*/
int match_equivalent_bytes_sets( cs_insn insn, struct hdr_data_message *data, unsigned char* output){
    int i,j,k,match=true,ret;
    /*
    *   ricordiamo che eq_inns_sets è formata da una lista di insiemi ( tabelle )
    *   ogni tabella contiene un'insieme di istruzioni, le quali hanno una lista
    *   contenente il machine code equivalente
    * */

    // per ogni tabella
    for ( j = 0; eq_insn_sets[j].table; j++)
    {
        if( insn.size != eq_insn_sets[j].byte_size ) continue;
        // per ogni istruzione
        for ( k = 0;  k < eq_insn_sets[j].table_size; k++)
        {
            // per ogni bytes
            for ( i = 0; i < eq_insn_sets[j].byte_size ; i++)
            {
                if( (unsigned char) insn.bytes[i] != eq_insn_sets[j].table[k].opcode[i]){
                    match = false;
                    break;
                }
            }
            if ( match ){
                /*if(eq_insn_sets[j].table_size == 6){
                    ret=take_bits( data, 2);
                    if((ret==0)||(ret==1)){
                        ret <<= 1;
                        ret |= take_bits( data, 1);
                    }else{

                    }
                }
                if(eq_insn_sets[j].table_size == 7){
                    ret=take_bits( data, 2);
                    if((ret==0)||(ret==1)||(ret==2)){
                        ret <<= 1;
                        ret |= take_bits( data, 1);
                    }
                }*/
                //TODO
                ret=take_bits( data, 2);
                for (  i = 0; i < eq_insn_sets[j].byte_size; i++ )
                {
                    output[i] = eq_insn_sets[j].table[ret].opcode[i];
                }
                return eq_insn_sets[ret].byte_size;   

            } else {
                match = true;
            }
        }
    }
    return error;
}

/*
*   controllo se matcha con toasxcN_table e ritorno l'indice, setto bits 
*/
int match_is_sets( cs_insn insn ){
    int i,j,k,match=true,ret;
    // per ogni tabella
    
    for ( j = 0; eq_insn_sets[j].table; j++)
    {
        if( insn.size != eq_insn_sets[j].byte_size ) continue;
        // per ogni istruzione
        for ( k = 0;  k < eq_insn_sets[j].table_size; k++)
        {
            // per ogni bytes
            for ( i = 0; i < eq_insn_sets[j].byte_size ; i++)
            {
                if( (unsigned char) insn.bytes[i] != eq_insn_sets[j].table[k].opcode[i]){
                    match = false;
                    break;
                }
            }
            if ( match ){
                return k;  
            } else {
                match = true;
            }
        }
    }
    return error;
}



/*
int match_insn( cs_insn insn , unsigned char* output){

    if( insn.id != X86_INS_TEST && 
        insn.id != X86_INS_OR   && 
        insn.id != X86_INS_AND  && 
        insn.id != X86_INS_ADD  && 
        insn.id != X86_INS_SUB  && 
        insn.id != X86_INS_XOR  && 
        insn.id != X86_INS_CMP 
    ) return error;
    
    
    // inizializzo keystone
    ks_engine *ks; // E' l'handle delle keystone API 
    ks_err err;
    size_t ks_count;
    size_t ks_size; // dimensione di encode

    int i,ret;
    char reverse_instr[ ADDSUB_INSTR_MAX_LEN ];
    unsigned char* ks_output;

    // declare temp op_str
    char op_str[160];
    strcpy( op_str, insn.op_str) ;

    
    //   controllo che source sia un imm8/16/31/64
    
    char * reg = strtok( op_str, OPERAND_DELIMITATOR);
    char * resto;
    
    char * imm = strtok(NULL, OPERAND_DELIMITATOR);
    int num = (int)strtol(imm, &resto, 16);
    // se num=0 c'è stato un errore, mentre se resto è != da una stringa vuota allora probabilmente 
    // ha letto un registro eax.. ha tradotto ea in num e messo x in resto --> errore 
    if( (num == 0) || ( *resto != '\x0' ) ){
        return error;
    }
    if( (ret = is_reg(reg)) >=0 ){
        //write_log("trovata %s %s, %d\n", insn.mnemonic, reg, num);
        if(insn.id == X86_INS_TEST ){
            if(num==-1){
                write_log("trovata %s %s, %d\n", insn.mnemonic, reg, num);
                cont_istr.test1++;
                //sleep(1);
            }else return error;
        }
        if(insn.id == X86_INS_OR ){
            if(num==0){
                write_log("trovata %s %s, %d\n", insn.mnemonic, reg, num);
                //sleep(1);
                cont_istr.or1++;
            }else return error;
        }
        if(insn.id == X86_INS_AND ){
            if(num==-1){
                write_log("trovata %s %s, %d\n", insn.mnemonic, reg, num);
                cont_istr.and1++;
                //sleep(1);
            }else return error;
        }
        if(insn.id == X86_INS_ADD ){
            if(num==0){
                write_log("trovata %s %s, %d\n", insn.mnemonic, reg, num);
                cont_istr.add1++;
                //sleep(1);
            }else return error;
        }
        if(insn.id == X86_INS_SUB ){
            if(num==0){
                write_log("trovata %s %s, %d\n", insn.mnemonic, reg, num);
                cont_istr.sub1++;
                //sleep(1);
            }else return error;
        }
        if(insn.id == X86_INS_XOR ){
            if(num==0){
                write_log("trovata %s %s, %d\n", insn.mnemonic, reg, num);
                cont_istr.xor1++;
                //sleep(1);
            }else return error;
        } 
        if(insn.id == X86_INS_CMP ){
            if(num==0){
                write_log("trovata %s %s, %d\n", insn.mnemonic, reg, num);
                cont_istr.cmp1++;
                //sleep(1);
            }else return error;
        }
        sprintf( reverse_instr, "and %s, 0", reg);
        write_log("%s\n", reverse_instr);
        // inizializza( architettura, ise, handle)
        err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks); 
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
            
            if( ks_size != insn.size ){
                return error;
            }
            //   nel caso della sostituzione ritorno la funzione da sostituire
            
            for (i = 0; i < ks_size; i++) {
                //write_log( "%02x ", ks_output[i]);
                output[i] = ks_output[i];
            }
            // close Keystone instance when done
            ks_free(ks_output);
            ks_close(ks);
            return ks_size;
        }
    }
    return error;
}  */ 




