
// includiamo tutte le specifiche 
#include "hidder.h"
const char *regs_h[] = {
        // registri 8 bit superiori
        REG_AH, REG_BH, REG_CH, REG_DH 
};
const char *regs[] = {
        // registri 8 bit
        REG_AL, REG_BL, REG_CL, REG_DL, REG_SIL, REG_DIL, REG_BPL, REG_SPL,
        REG_R8B, REG_R9B, REG_R10B, REG_R11B, REG_R12B, REG_R13B, REG_R14B, REG_R15B,
        // registri 16 bit
        REG_AX, REG_BX, REG_CX, REG_DX, REG_SI, REG_DI, REG_BP, REG_SP, REG_R8W,
        REG_R9W, REG_R10W, REG_R11W, REG_R12W, REG_R13W, REG_R14W, REG_R15W,
        // registri 32 bit
        REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI, REG_EBP, REG_ESP,
        REG_R8D, REG_R9D, REG_R10D, REG_R11D, REG_R12D, REG_R13D, REG_R14D, REG_R15D,
        // registri 64 bit
        REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI, REG_RBP, REG_RSP,
        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15
};

void print_reg(){
    int i;
    for ( i = 0; i < ( 4 * REG_NUMBER ); i++)
    {
        write_log( "%s ", regs[i] );
    }
}

int hdr_is_RET( int id){
    if ((id==X86_INS_RET)  || 
        (id==X86_INS_RETF)  ||
        (id==X86_INS_RETFQ)  ||
        (id==X86_INS_IRET)  ||
        (id==X86_INS_IRETD)  ||
        (id==X86_INS_IRETQ)  ||
        (id==X86_INS_SYSRET)  
    ) return true;
    return false;
}

int hdr_is_JUMP( int id){
    if ((id==X86_INS_JA)  || 
        (id==X86_INS_JAE)  || 
        (id==X86_INS_JB)  || 
        (id==X86_INS_JBE)  || 
        (id==X86_INS_JCXZ)  || 
        (id==X86_INS_JE)  || 
        (id==X86_INS_JECXZ)  || 
        (id==X86_INS_JG)  || 
        (id==X86_INS_JGE)  || 
        (id==X86_INS_JL)  || 
        (id==X86_INS_JLE)  || 
        (id==X86_INS_JMP)  || 
        (id==X86_INS_JNE)  || 
        (id==X86_INS_JNO)  || 
        (id==X86_INS_JNP)  || 
        (id==X86_INS_JNS)  || 
        (id==X86_INS_JO)  || 
        (id==X86_INS_JNO)  || 
        (id==X86_INS_JP)  || 
        (id==X86_INS_JRCXZ)  || 
        (id==X86_INS_JS)  || 
        (id==X86_INS_JNS)  || 
        (id==X86_INS_LJMP)   
    ) return true;
    return false;
}

int hdr_is_CALL( int id){
    if ((id==X86_INS_CALL)  || 
        (id==X86_INS_LCALL)  ||
        (id==X86_INS_VMCALL)  ||
        (id==X86_INS_SYSCALL)  ||
        (id==X86_INS_VMMCALL)  
    ) return true;
    return false;
}

int flag_reg( const char* str){
    int i;
    for ( i = 0; i < (REG_NUMBER*REG_TYPE) ; i++)
    {
        if(strcmp(str, regs[i])==0)
        {
            return i;
        }
    }
    return error;
}

/*
*   controlla se str equivale ad un registro,
*   i registri sono salvati in una var globale char regs[] in ordine,
*   prima i registri da 8 bit poi 16, 32 e infine 64.
*   ritorna -1 se non è un registro, altrimenti un intero che ne indica:
*   dimensione del registro + se fa parte degli 8 registri addizionali r8..r15
*   es REG_R + REG_16_BIT, indichera con i primi 2 bit la dimensione e con il 3 bit se R o meno
*/
int is_reg( char* str ){
    int i;

    for ( i = 0; i < (REG_NUMBER*REG_TYPE) ; i++)
    {
        if(strcmp(str, regs[i])==0)
        {
            return ( ( (i%REG_NUMBER)/(REG_NUMBER/2) ) << 2 ) | ( i / REG_NUMBER );
        }
    }

    return error;
}




int check_flag( cs_insn* isns, int flags, int index, int num_ists ){
    int i;
    uint64_t isns_flag;
    /*
    *   per ogni istruzione
    */
    for ( i = (index+1) ; i < num_ists; i++)
    {
        if( is_skipdata(isns[i].id) ) continue;
        /*
        *   Ritorniamo true poiche queste operazioni "annullano" il valore attuale dei flag
        *   poiche per convenzione durante una ret/leave/call i flag non vengono portati a meno 
        *   di una specifica pushf/popf.
        *   Ovviamente se viene effettuata una popf sovrascrive tutti i flag.
        *   Idem per PUSHF salva lo stato dei flag errato e quindi ritorniamo false. 
        */
        if( (isns[i].id == X86_INS_RET)      || 
            (isns[i].id == X86_INS_LEAVE )   || 
            (isns[i].id == X86_INS_POPF )    ||
            (isns[i].id == X86_INS_POPFD)    ||
            (isns[i].id == X86_INS_CALL)     ||
            (isns[i].id == X86_INS_POPFQ )   ){

                return true;
        } 

        /*
        *   per i jump incondizionati dovremmo seguirli, ma i salti relativi creano problemi
        *   quindi al momento ritorniamo false insieme ai pushf
        */
        if( (isns[i].id == X86_INS_JMP )     || 
            (isns[i].id == X86_INS_PUSHF )   ||
            (isns[i].id == X86_INS_PUSHFD )  ||
            (isns[i].id == X86_INS_PUSHFQ )  ){

                return false;
        } 
        
        /*
        *   passiamo al controllo di ogni altra istruzione 
        */
        isns_flag = isns[i].detail->x86.eflags;
        
        


        // controllo se i flags cambiati sono utilizzati
        if ((flags & CF) && (isns_flag & X86_EFLAGS_TEST_CF)) return false;
        if ((flags & ZF) && (isns_flag & X86_EFLAGS_TEST_ZF)) return false;
        if ((flags & OF) && (isns_flag & X86_EFLAGS_TEST_OF)) return false;
        if ((flags & DF) && (isns_flag & X86_EFLAGS_TEST_DF)) return false;
        if ((flags & SF) && (isns_flag & X86_EFLAGS_TEST_SF)) return false;
        if ((flags & AF) && (isns_flag & X86_EFLAGS_TEST_AF)) return false;
        if ((flags & PF) && (isns_flag & X86_EFLAGS_TEST_PF)) return false;
        


        // cancello dalla lista dei flag cambiati, se sovrascritti
        if ((isns_flag & X86_EFLAGS_MODIFY_CF)  || (isns_flag & X86_EFLAGS_RESET_CF)  || (isns_flag & X86_EFLAGS_SET_CF)) {
                //write_log(  "%s MODIFICA CF\n", isns[i].mnemonic );
                flags &= ~CF;
            }
        if ((isns_flag & X86_EFLAGS_MODIFY_PF)  || (isns_flag & X86_EFLAGS_RESET_PF) ||
            (isns_flag & X86_EFLAGS_UNDEFINED_PF)  || (isns_flag & X86_EFLAGS_SET_PF)) {
                //write_log(  "%s MODIFICA PF\n", isns[i].mnemonic );
                flags &= ~PF;
            }
        if ((isns_flag & X86_EFLAGS_MODIFY_OF)  || (isns_flag & X86_EFLAGS_RESET_OF) || (isns_flag & X86_EFLAGS_SET_OF)) {
                //write_log(  "%s MODIFICA OF\n", isns[i].mnemonic );
                flags &= ~OF;
            }
        if ((isns_flag & X86_EFLAGS_MODIFY_ZF)  || (isns_flag & X86_EFLAGS_RESET_ZF) ||
            (isns_flag & X86_EFLAGS_UNDEFINED_ZF)  || (isns_flag & X86_EFLAGS_SET_ZF)) {
                //write_log(  "%s MODIFICA ZF\n", isns[i].mnemonic );
                flags &= ~ZF;
            }
        if ((isns_flag & X86_EFLAGS_MODIFY_DF)  || (isns_flag & X86_EFLAGS_RESET_DF) ||
              (isns_flag & X86_EFLAGS_SET_DF)) {
                //write_log(  "%s MODIFICA DF\n", isns[i].mnemonic );
                flags &= ~DF;
            }
        if ((isns_flag & X86_EFLAGS_MODIFY_SF)  || (isns_flag & X86_EFLAGS_RESET_SF) || (isns_flag & X86_EFLAGS_SET_SF)) {
                //write_log(  "%s MODIFICA SF\n", isns[i].mnemonic );
                flags &= ~SF;
            }
        if ((isns_flag & X86_EFLAGS_MODIFY_AF)  || (isns_flag & X86_EFLAGS_RESET_AF) ||
            (isns_flag & X86_EFLAGS_UNDEFINED_AF)  || (isns_flag & X86_EFLAGS_SET_AF)) {
                //write_log(  "%s MODIFICA AF\n", isns[i].mnemonic );
                flags &= ~AF;
            }
            
        // se non ho piu flag nella lista dei flag cambiati posso uscire con successo
        if( flags == NF ){
            return true;
        } 
    }
    return true;
}



char *get_eflag_name(uint64_t flag)
{
	switch(flag) {
		default:
			return NULL;
		case X86_EFLAGS_UNDEFINED_OF:
			return "UNDEF_OF";
		case X86_EFLAGS_UNDEFINED_SF:
			return "UNDEF_SF";
		case X86_EFLAGS_UNDEFINED_ZF:
			return "UNDEF_ZF";
		case X86_EFLAGS_MODIFY_AF:
			return "MOD_AF";
		case X86_EFLAGS_UNDEFINED_PF:
			return "UNDEF_PF";
		case X86_EFLAGS_MODIFY_CF:
			return "MOD_CF";
		case X86_EFLAGS_MODIFY_SF:
			return "MOD_SF";
		case X86_EFLAGS_MODIFY_ZF:
			return "MOD_ZF";
		case X86_EFLAGS_UNDEFINED_AF:
			return "UNDEF_AF";
		case X86_EFLAGS_MODIFY_PF:
			return "MOD_PF";
		case X86_EFLAGS_UNDEFINED_CF:
			return "UNDEF_CF";
		case X86_EFLAGS_MODIFY_OF:
			return "MOD_OF";
		case X86_EFLAGS_RESET_OF:
			return "RESET_OF";
		case X86_EFLAGS_RESET_CF:
			return "RESET_CF";
		case X86_EFLAGS_RESET_DF:
			return "RESET_DF";
		case X86_EFLAGS_RESET_IF:
			return "RESET_IF";
		case X86_EFLAGS_TEST_OF:
			return "TEST_OF";
		case X86_EFLAGS_TEST_SF:
			return "TEST_SF";
		case X86_EFLAGS_TEST_ZF:
			return "TEST_ZF";
		case X86_EFLAGS_TEST_PF:
			return "TEST_PF";
		case X86_EFLAGS_TEST_CF:
			return "TEST_CF";
		case X86_EFLAGS_RESET_SF:
			return "RESET_SF";
		case X86_EFLAGS_RESET_AF:
			return "RESET_AF";
		case X86_EFLAGS_RESET_TF:
			return "RESET_TF";
		case X86_EFLAGS_RESET_NT:
			return "RESET_NT";
		case X86_EFLAGS_PRIOR_OF:
			return "PRIOR_OF";
		case X86_EFLAGS_PRIOR_SF:
			return "PRIOR_SF";
		case X86_EFLAGS_PRIOR_ZF:
			return "PRIOR_ZF";
		case X86_EFLAGS_PRIOR_AF:
			return "PRIOR_AF";
		case X86_EFLAGS_PRIOR_PF:
			return "PRIOR_PF";
		case X86_EFLAGS_PRIOR_CF:
			return "PRIOR_CF";
		case X86_EFLAGS_PRIOR_TF:
			return "PRIOR_TF";
		case X86_EFLAGS_PRIOR_IF:
			return "PRIOR_IF";
		case X86_EFLAGS_PRIOR_DF:
			return "PRIOR_DF";
		case X86_EFLAGS_TEST_NT:
			return "TEST_NT";
		case X86_EFLAGS_TEST_DF:
			return "TEST_DF";
		case X86_EFLAGS_RESET_PF:
			return "RESET_PF";
		case X86_EFLAGS_PRIOR_NT:
			return "PRIOR_NT";
		case X86_EFLAGS_MODIFY_TF:
			return "MOD_TF";
		case X86_EFLAGS_MODIFY_IF:
			return "MOD_IF";
		case X86_EFLAGS_MODIFY_DF:
			return "MOD_DF";
		case X86_EFLAGS_MODIFY_NT:
			return "MOD_NT";
		case X86_EFLAGS_MODIFY_RF:
			return "MOD_RF";
		case X86_EFLAGS_SET_CF:
			return "SET_CF";
		case X86_EFLAGS_SET_DF:
			return "SET_DF";
		case X86_EFLAGS_SET_IF:
			return "SET_IF";
	}
}
