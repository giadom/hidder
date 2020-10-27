// includiamo tutte le specifiche 
#include "hidder.h"

/*
 * i seguenti sets sono uguali solamente quando usano gli stessi
 * registers.  istruzione uguale flag invariati..
 */
struct table add8_s[] =
{
    {{'\x00'}, NF, "add  r/m8 , r8"   },
    {{'\x02'}, NF, "add  r8   , r/m8" },
};
struct table add16_s[] =
{
    {{'\x66','\x01'}, NF, "add  r/m16, r16"   },
    {{'\x66','\x03'}, NF, "add  r16  , r/m16" },
};
struct table add32_s[] =
{
    {{'\x01'}, NF, "add  r/m32, r32"   },
    {{'\x03'}, NF, "add  r32  , r/m32" },
};
struct table add64_s[] =
{
    {{'\x48','\x01'}, NF, "add  r/m64, r64"   },
    {{'\x48','\x03'}, NF, "add  r64  , r/m64" },
};

// ADC ISTRUCTION R/M, R
struct table adc8_s[] =
{
    {{'\x10'}, NF, "adc  r/m8 , r8"   },
    {{'\x12'}, NF, "adc  r8   , r/m8" },
};
struct table adc16_s[] =
{
    {{'\x66','\x11'}, NF, "adc  r/m16, r16"   },
    {{'\x66','\x13'}, NF, "adc  r16  , r/m16" },
};
struct table adc32_s[] =
{
    {{'\x11'}, NF, "adc  r/m32, r32"   },
    {{'\x13'}, NF, "adc  r32  , r/m32" },
};
struct table adc64_s[] =
{
    {{'\x48','\x11'}, NF, "adc  r/m64, r64"   },
    {{'\x48','\x13'}, NF, "adc  r64  , r/m64" },
};

// CMP ISTRUCTION R/M, R
struct table cmp8_s[] =
{
    {{'\x38'}, NF, "cmp  r/m8 , r8"   },
    {{'\x3A'}, NF, "cmp  r8   , r/m8" },
};
struct table cmp16_s[] =
{
    {{'\x66','\x39'}, NF, "cmp  r/m16, r16"   },
    {{'\x66','\x3B'}, NF, "cmp  r16  , r/m16" },
};
struct table cmp32_s[] =
{
    {{'\x39'}, NF, "cmp  r/m32, r32"   },
    {{'\x3B'}, NF, "cmp  r32  , r/m32" },
};
struct table cmp64_s[] =
{
    {{'\x48','\x39'}, NF, "cmp  r/m64, r64"   },
    {{'\x48','\x3B'}, NF, "cmp  r64  , r/m64" },
};

// MOV ISTRUCTION R/M, R
struct table mov8_s[] =
{
    {{'\x88'}, NF, "mov  r/m8 , r8"   },
    {{'\x8A'}, NF, "mov  r8   , r/m8" },
};
struct table mov16_s[] =
{
    {{'\x66','\x89'}, NF, "mov  r/m16, r16"   },
    {{'\x66','\x8B'}, NF, "mov  r16  , r/m16" },
};
struct table mov32_s[] =
{
    {{'\x89'}, NF, "mov  r/m32, r32"   },
    {{'\x8B'}, NF, "mov  r32  , r/m32" },
};
struct table mov64_s[] =
{
    {{'\x48','\x89'}, NF, "mov  r/m64, r64"   },
    {{'\x48','\x8B'}, NF, "mov  r64  , r/m64" },
};

// SBB ISTRUCTION R/M, R
struct table sbb8_s[] =
{
    {{'\x18'}, NF, "sbb  r/m8 , r8"   },
    {{'\x1A'}, NF, "sbb  r8   , r/m8" },
};
struct table sbb16_s[] =
{
    {{'\x66','\x19'}, NF, "sbb  r/m16, r16"   },
    {{'\x66','\x1B'}, NF, "sbb  r16  , r/m16" },
};
struct table sbb32_s[] =
{
    {{'\x19'}, NF, "sbb  r/m32, r32"   },
    {{'\x1B'}, NF, "sbb  r32  , r/m32" },
};
struct table sbb64_s[] =
{
    {{'\x48','\x19'}, NF, "sbb  r/m64, r64"   },
    {{'\x48','\x1B'}, NF, "sbb  r64  , r/m64" },
};



int aacms_s( cs_insn insn, struct hdr_data_message *data, unsigned char* output ){
    
    if( insn.id != X86_INS_ADD && 
        insn.id != X86_INS_ADC && 
        insn.id != X86_INS_CMP && 
        insn.id != X86_INS_MOV && 
        insn.id != X86_INS_SBB 
        ){ return error;
    }
    // declare temp op_str
    char op_str[160];
    strcpy( op_str, insn.op_str) ;
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
    if( ( strcmp( reg1, &reg2[1] )==0 ) && ( (ret = is_reg(reg1)) >=0 ) ){
        
        if( insn.id == X86_INS_ADD) cont_istr.add++;
        if( insn.id == X86_INS_ADC) cont_istr.adc++;
        if( insn.id == X86_INS_CMP) cont_istr.cmp++;
        if( insn.id == X86_INS_MOV) cont_istr.mov++;
        if( insn.id == X86_INS_SBB) cont_istr.sbb++;
        switch(ret){
            case REG_8_BIT:
                bit = take_bits( data, 1 );
                
                if( insn.bytes[0] == '\x40' ){
                    output[0] = '\x40';
                    if( insn.id == X86_INS_ADD) output[1] = add8_s[bit].opcode[0];
                    if( insn.id == X86_INS_ADC) output[1] = adc8_s[bit].opcode[0];
                    if( insn.id == X86_INS_CMP) output[1] = cmp8_s[bit].opcode[0];
                    if( insn.id == X86_INS_MOV) output[1] = mov8_s[bit].opcode[0];
                    if( insn.id == X86_INS_SBB) output[1] = sbb8_s[bit].opcode[0];
                    return 2;
                }else{
                    if( insn.id == X86_INS_ADD) output[0] = add8_s[bit].opcode[0];
                    if( insn.id == X86_INS_ADC) output[0] = adc8_s[bit].opcode[0];
                    if( insn.id == X86_INS_CMP) output[0] = cmp8_s[bit].opcode[0];
                    if( insn.id == X86_INS_MOV) output[0] = mov8_s[bit].opcode[0];
                    if( insn.id == X86_INS_SBB) output[0] = sbb8_s[bit].opcode[0];
                    return 1;
                }
            case REG_16_BIT:
            
                bit = take_bits( data, 1 );
                if( insn.id == X86_INS_ADD) strncpy(output, add16_s[bit].opcode, 2);
                if( insn.id == X86_INS_ADC) strncpy(output, adc16_s[bit].opcode, 2);
                if( insn.id == X86_INS_CMP) strncpy(output, cmp16_s[bit].opcode, 2);
                if( insn.id == X86_INS_MOV) strncpy(output, mov16_s[bit].opcode, 2);
                if( insn.id == X86_INS_SBB) strncpy(output, sbb16_s[bit].opcode, 2);
                return 2;
            case REG_32_BIT:
            
                bit = take_bits( data, 1 );
                if( insn.id == X86_INS_ADD) output[0] = add32_s[bit].opcode[0];
                if( insn.id == X86_INS_ADC) output[0] = adc32_s[bit].opcode[0];
                if( insn.id == X86_INS_CMP) output[0] = cmp32_s[bit].opcode[0];
                if( insn.id == X86_INS_MOV) output[0] = mov32_s[bit].opcode[0];
                if( insn.id == X86_INS_SBB) output[0] = sbb32_s[bit].opcode[0];
                return 1;
            case REG_64_BIT:
            
                bit = take_bits( data, 1 );
                if( insn.id == X86_INS_ADD) strncpy(output, add64_s[bit].opcode, 2);
                if( insn.id == X86_INS_ADC) strncpy(output, adc64_s[bit].opcode, 2);
                if( insn.id == X86_INS_CMP) strncpy(output, cmp64_s[bit].opcode, 2);
                if( insn.id == X86_INS_MOV) strncpy(output, mov64_s[bit].opcode, 2);
                if( insn.id == X86_INS_SBB) strncpy(output, sbb64_s[bit].opcode, 2);
                return 2;
            /*
            *   i registri R utilizzano lo stesso codice macchina ma con un prefisso
            */
            case (REG_8_BIT | REG_R_TYPE):
            
                bit = take_bits( data, 1 );
                output[0] = R_REGS_PREFIX;
                if( insn.id == X86_INS_ADD) output[1] = add8_s[bit].opcode[0];
                if( insn.id == X86_INS_ADC) output[1] = adc8_s[bit].opcode[0];
                if( insn.id == X86_INS_CMP) output[1] = cmp8_s[bit].opcode[0];
                if( insn.id == X86_INS_MOV) output[1] = mov8_s[bit].opcode[0];
                if( insn.id == X86_INS_SBB) output[1] = sbb8_s[bit].opcode[0];
                return 2;
            case (REG_16_BIT | REG_R_TYPE):
            
                bit = take_bits( data, 1 );
                if( insn.id == X86_INS_ADD){ 
                    output[0] = add16_s[bit].opcode[0];
                    output[2] = add16_s[bit].opcode[1];
                }
                if( insn.id == X86_INS_ADC){ 
                    output[0] = adc16_s[bit].opcode[0];
                    output[2] = adc16_s[bit].opcode[1];
                }
                if( insn.id == X86_INS_CMP){ 
                    output[0] = cmp16_s[bit].opcode[0];
                    output[2] = cmp16_s[bit].opcode[1];
                }
                if( insn.id == X86_INS_MOV){ 
                    output[0] = mov16_s[bit].opcode[0];
                    output[2] = mov16_s[bit].opcode[1];
                }
                if( insn.id == X86_INS_SBB){ 
                    output[0] = sbb16_s[bit].opcode[0];
                    output[2] = sbb16_s[bit].opcode[1];
                }
                output[1] = R_REGS_PREFIX;
                return 3;
            case (REG_R_TYPE | REG_32_BIT):
            
                bit = take_bits( data, 1 );
                output[0] = R_REGS_PREFIX;
                if( insn.id == X86_INS_ADD) output[1] = add32_s[bit].opcode[0];
                if( insn.id == X86_INS_ADC) output[1] = adc32_s[bit].opcode[0];
                if( insn.id == X86_INS_CMP) output[1] = cmp32_s[bit].opcode[0];
                if( insn.id == X86_INS_MOV) output[1] = mov32_s[bit].opcode[0];
                if( insn.id == X86_INS_SBB) output[1] = sbb32_s[bit].opcode[0];
                return 2;
            case (REG_64_BIT | REG_R_TYPE ):
            
                bit = take_bits( data, 1 );
                output[0] = R_64_BIT_REGS_PREFIX;
                if( insn.id == X86_INS_ADD) output[1] = add64_s[bit].opcode[1];
                if( insn.id == X86_INS_ADC) output[1] = adc64_s[bit].opcode[1];
                if( insn.id == X86_INS_CMP) output[1] = cmp64_s[bit].opcode[1];
                if( insn.id == X86_INS_MOV) output[1] = mov64_s[bit].opcode[1];
                if( insn.id == X86_INS_SBB) output[1] = sbb64_s[bit].opcode[1];
                return 2;
            default:
                write_log("Qualcosa è andato storto %s %s,%s is_reg()=%d\n",insn.mnemonic,reg1, &reg2[1],ret);
                return error;
        }
    }
    return error;

}




int aacms_is_s( cs_insn insn ){

    if( insn.id != X86_INS_ADD && 
        insn.id != X86_INS_ADC && 
        insn.id != X86_INS_CMP && 
        insn.id != X86_INS_MOV && 
        insn.id != X86_INS_SBB 
        ){ return error;
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
    if( ( strcmp( reg1, &reg2[1] )==0 ) && ( (ret = is_reg(reg1)) >=0) ){
        
        switch(ret){
            case REG_8_BIT:
            
                if( insn.id == X86_INS_ADD){
                    if ( insn.bytes[0] == add8_s[0].opcode[0] ) return 0;
                    else return 1;
                } 
                if( insn.id == X86_INS_ADC){
                    if ( insn.bytes[0] == adc8_s[0].opcode[0] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_CMP){
                    if ( insn.bytes[0] == cmp8_s[0].opcode[0] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_MOV){
                    if ( insn.bytes[0] == mov8_s[0].opcode[0] ) return 0;
                    else return 1;
                }
                if( insn.id == X86_INS_SBB){
                    if ( insn.bytes[0] == sbb8_s[0].opcode[0] ) return 0;
                    else return 1;
                }
            case REG_16_BIT:
            
                if( insn.id == X86_INS_ADD){
                    if ( insn.bytes[1] == add16_s[0].opcode[1] ) return 0;
                    else return 1;
                } 
                if( insn.id == X86_INS_ADC){
                    if ( insn.bytes[1] == adc16_s[0].opcode[1] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_CMP){
                    if ( insn.bytes[1] == cmp16_s[0].opcode[1] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_MOV){
                    if ( insn.bytes[1] == mov16_s[0].opcode[1] ) return 0;
                    else return 1;
                }
                if( insn.id == X86_INS_SBB){
                    if ( insn.bytes[1] == sbb16_s[0].opcode[1] ) return 0;
                    else return 1;
                }
            case REG_32_BIT:
            
                if( insn.id == X86_INS_ADD){
                    if ( insn.bytes[0] == add32_s[0].opcode[0] ) return 0;
                    else return 1;
                } 
                if( insn.id == X86_INS_ADC){
                    if ( insn.bytes[0] == adc32_s[0].opcode[0] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_CMP){
                    if ( insn.bytes[0] == cmp32_s[0].opcode[0] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_MOV){
                    if ( insn.bytes[0] == mov32_s[0].opcode[0] ) return 0;
                    else return 1;
                }
                if( insn.id == X86_INS_SBB){
                    if ( insn.bytes[0] == sbb32_s[0].opcode[0] ) return 0;
                    else return 1;
                }
            case REG_64_BIT:
            
                if( insn.id == X86_INS_ADD){
                    if ( insn.bytes[1] == add64_s[0].opcode[1] ) return 0;
                    else return 1;
                } 
                if( insn.id == X86_INS_ADC){
                    if ( insn.bytes[1] == adc64_s[0].opcode[1] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_CMP){
                    if ( insn.bytes[1] == cmp64_s[0].opcode[1] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_MOV){
                    if ( insn.bytes[1] == mov64_s[0].opcode[1] ) return 0;
                    else return 1;
                }
                if( insn.id == X86_INS_SBB){
                    if ( insn.bytes[1] == sbb64_s[0].opcode[1] ) return 0;
                    else return 1;
                }
            /*
            *   i registri R utilizzano lo stesso codice macchina ma con un prefisso
            */
            case (REG_8_BIT | REG_R_TYPE):
            
                if( insn.id == X86_INS_ADD){
                    if ( insn.bytes[1] == add8_s[0].opcode[0] ) return 0;
                    else return 1;
                } 
                if( insn.id == X86_INS_ADC){
                    if ( insn.bytes[1] == adc8_s[0].opcode[0] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_CMP){
                    if ( insn.bytes[1] == cmp8_s[0].opcode[0] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_MOV){
                    if ( insn.bytes[1] == mov8_s[0].opcode[0] ) return 0;
                    else return 1;
                }
                if( insn.id == X86_INS_SBB){
                    if ( insn.bytes[1] == sbb8_s[0].opcode[0] ) return 0;
                    else return 1;
                }
            case (REG_16_BIT | REG_R_TYPE):
            
                if( insn.id == X86_INS_ADD){
                    if ( insn.bytes[2] == add16_s[0].opcode[1] ) return 0;
                    else return 1;
                } 
                if( insn.id == X86_INS_ADC){
                    if ( insn.bytes[2] == adc16_s[0].opcode[1] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_CMP){
                    if ( insn.bytes[2] == cmp16_s[0].opcode[1] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_MOV){
                    if ( insn.bytes[2] == mov16_s[0].opcode[1] ) return 0;
                    else return 1;
                }
                if( insn.id == X86_INS_SBB){
                    if ( insn.bytes[2] == sbb16_s[0].opcode[1] ) return 0;
                    else return 1;
                }
            case (REG_R_TYPE | REG_32_BIT):
            
                if( insn.id == X86_INS_ADD){
                    if ( insn.bytes[1] == add32_s[0].opcode[0] ) return 0;
                    else return 1;
                } 
                if( insn.id == X86_INS_ADC){
                    if ( insn.bytes[1] == adc32_s[0].opcode[0] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_CMP){
                    if ( insn.bytes[1] == cmp32_s[0].opcode[0] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_MOV){
                    if ( insn.bytes[1] == mov32_s[0].opcode[0] ) return 0;
                    else return 1;
                }
                if( insn.id == X86_INS_SBB){
                    if ( insn.bytes[1] == sbb32_s[0].opcode[0] ) return 0;
                    else return 1;
                }
            case (REG_64_BIT | REG_R_TYPE ):
            
                if( insn.id == X86_INS_ADD){
                    if ( insn.bytes[1] == add64_s[0].opcode[1] ) return 0;
                    else return 1;
                } 
                if( insn.id == X86_INS_ADC){
                    if ( insn.bytes[1] == adc64_s[0].opcode[1] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_CMP){
                    if ( insn.bytes[1] == cmp64_s[0].opcode[1] ) return 0;
                    else return 1;
                }  
                if( insn.id == X86_INS_MOV){
                    if ( insn.bytes[1] == mov64_s[0].opcode[1] ) return 0;
                    else return 1;
                }
                if( insn.id == X86_INS_SBB){
                    if ( insn.bytes[1] == sbb64_s[0].opcode[1] ) return 0;
                    else return 1;
                }
            default:
                write_log("Qualcosa è andato storto %s %s,%s is_reg()=%d\n",insn.mnemonic,reg1, &reg2[1],ret);
                return error;
        }
    }
    return error;

}