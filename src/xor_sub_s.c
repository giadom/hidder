// includiamo tutte le specifiche 
#include "hidder.h"

/*
 * clear register instructions: only works on registers (mod == 3),
 * since result is stored in destination, and the source and
 * destination operands must be the same (RR).
 * Flags affected are identical, since an xor is a sub anyways.
 */
struct table xor_sub8_s[] =
{
    { {'\x30'},  NF, "xor  r/m8 , r8"   },
    { {'\x32'},  NF, "xor  r8   , r/m8" },
    { {'\x28'},  NF, "sub  r/m8 , r8"   },
    { {'\x2A'},  NF, "sub  r8   , r/m8" },
};
struct table xor_sub16_s[] =
{
    { {'\x66','\x31'},  NF, "xor  r/m16, r16"   },
    { {'\x66','\x33'},  NF, "xor  r16  , r/m16" },
    { {'\x66','\x29'},  NF, "sub  r/m16, r16"   },
    { {'\x66','\x2B'},  NF, "sub  r16  , r/m16" },
};
struct table xor_sub32_s[] =
{
    { {'\x31'},  NF, "xor  r/m32, r32"   },
    { {'\x33'},  NF, "xor  r32  , r/m32" },
    { {'\x29'},  NF, "sub  r/m32, r32"   },
    { {'\x2B'},  NF, "sub  r32  , r/m32" },
};
struct table xor_sub64_s[] =
{
    { {'\x48','\x31'},  NF, "xor  r/m64, r64"   },
    { {'\x48','\x33'},  NF, "xor  r64  , r/m64" },
    { {'\x48','\x29'},  NF, "sub  r/m64, r64"   },
    { {'\x48','\x2B'},  NF, "sub  r64  , r/m64" },
};



int xor_sub_subs( cs_insn isns, struct hdr_data_message *data, unsigned char* output ){
    if( isns.id != X86_INS_XOR && isns.id != X86_INS_SUB ){
        return error;
    }
    // declare temp op_str
    char op_str[160];
    strcpy( op_str, isns.op_str) ;
    
    /*
    *   controllo che r/m == r
    */
    char * reg1 = NULL;
    char * reg2 = NULL;
    int ret=0;
    uint8_t bit=0;
    reg1 = strtok( op_str, OPERAND_DELIMITATOR);
    reg2 = strtok(NULL, OPERAND_DELIMITATOR);
    if( reg1 == NULL || reg2==NULL){
        return error;
    }
    ret = is_reg(reg1);
    if( ( strcmp( reg1,&reg2[1] )==0 ) && (  ret>=0 ) ){
        
        if( isns.id == X86_INS_XOR) cont_istr.xor++;
        if( isns.id == X86_INS_SUB) cont_istr.sub_x++;
     
        switch(ret){
            case REG_8_BIT:
                
                bit = take_bits( data, 2 );
                
                if( isns.bytes[0] == '\x40' ){
                    output[0] = '\x40';
                    output[1] = xor_sub8_s[bit].opcode[0];
                    return 2;
                }else{
                    output[0] = xor_sub8_s[bit].opcode[0];
                    return 1;
                }
            case REG_16_BIT:
            
                bit = take_bits( data, 2 );
                output[0] = xor_sub16_s[bit].opcode[0];
                output[1] = xor_sub16_s[bit].opcode[1];
                return 2;
            case REG_32_BIT:
            
                bit = take_bits( data, 2 );
                output[0] = xor_sub32_s[bit].opcode[0];
                return 1;
            case REG_64_BIT:
            
                bit = take_bits( data, 2 );
                output[0] = xor_sub64_s[bit].opcode[0];
                output[1] = xor_sub64_s[bit].opcode[1];
                return 2;

            case (REG_8_BIT | REG_R_TYPE):
            
                bit = take_bits( data, 2 );
                output[0] = R_REGS_PREFIX;
                output[1] = xor_sub8_s[bit].opcode[0];
                return 2;
            case (REG_16_BIT | REG_R_TYPE):
            
                bit = take_bits( data, 2 );
                output[0] = xor_sub16_s[bit].opcode[0];
                output[1] = R_REGS_PREFIX;
                output[2] = xor_sub16_s[bit].opcode[1];
                return 3;
            case (REG_R_TYPE | REG_32_BIT):
            
                bit = take_bits( data, 2 );
                output[0] = R_REGS_PREFIX;
                output[1] = xor_sub32_s[bit].opcode[0];
                return 2;
            case (REG_64_BIT | REG_R_TYPE ):
            
                bit = take_bits( data, 2 );
                output[0] = R_64_BIT_REGS_PREFIX;
                output[1] = xor_sub64_s[bit].opcode[1];
                return 2;
            default:
                write_log("Qualcosa è andato storto %s %s,%s is_reg()=%d\n",isns.mnemonic,reg1,&reg2[1],ret);
                return error;
        }
    }
    return error;

}



int xor_sub_is_subs( cs_insn isns ){
    if( isns.id != X86_INS_XOR && isns.id != X86_INS_SUB ){
        return error;
    }
    // declare temp op_str
    char op_str[160];
    strcpy( op_str, isns.op_str ) ;
    
    /*
    *   controllo che r/m == r
    */
    char * reg1 = strtok( op_str, OPERAND_DELIMITATOR );
    char * reg2;
    int ret,i;
    reg2 = strtok( NULL, OPERAND_DELIMITATOR );
    if( reg1 == NULL || reg2==NULL){
        return error;
    }
    if( ( strcmp( reg1, &reg2[1] )==0 ) && ( (ret = is_reg(reg1)) >=0 ) ){
        
        switch(ret){
            case REG_8_BIT:
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( isns.bytes[0] == xor_sub8_s[i].opcode[0] ){
                        return i;
                    }
                }
            case REG_16_BIT:
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( isns.bytes[1] == xor_sub16_s[i].opcode[1] ){
                        return i;
                    }
                }
            case REG_32_BIT:
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( isns.bytes[0] == xor_sub32_s[i].opcode[0] ){
                        return i;
                    }
                }
            case REG_64_BIT:
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( isns.bytes[1] == xor_sub64_s[i].opcode[1] ){
                        return i;
                    }
                }

            case (REG_8_BIT | REG_R_TYPE):
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( isns.bytes[1] == xor_sub8_s[i].opcode[0] ){
                        return i;
                    }
                }
            case (REG_16_BIT | REG_R_TYPE):
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( isns.bytes[2] == xor_sub16_s[i].opcode[1] ){
                        return i;
                    }
                }
            case (REG_R_TYPE | REG_32_BIT):
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( isns.bytes[1] == xor_sub32_s[i].opcode[0] ){
                        return i;
                    }
                }
            case (REG_64_BIT | REG_R_TYPE ):
            
                for ( i = 0; i < TOA_TABLE_SIZE; i++)
                {
                    if( isns.bytes[1] == xor_sub64_s[i].opcode[1] ){
                        return i;
                    }
                }
            default:
                write_log("Qualcosa è andato storto %s %s,%s is_reg()=%d\n",isns.mnemonic,reg1,&reg2[1],ret);
                return error;
        }
    }
    return error;

}




