// header libreria
#include "hidder.h"
  
int binarySearch(int arr[], int low, int high, int key)
{
    if (high < low)
        return -1;
    int mid = (low + high) / 2; 
    if (key == arr[mid])
        return mid;
    if (key > arr[mid])
        return binarySearch(arr, (mid + 1), high, key);
    return binarySearch(arr, low, (mid - 1), key);
}
int insertSorted(int arr[], int n, int key)
{
    int i;
    for (i = n - 1; (i >= 0 && arr[i] > key); i--)
        arr[i + 1] = arr[i];
 
    arr[i + 1] = key;
 
    return (n + 1);
}

int disasm( unsigned char* CODE, int size){
    // variabili multi uso per return cicli e temporanei
    int i,ret;
    
    unsigned char temp;
    // inizializzo capstone
	csh handle;
	cs_insn *insn;
	size_t count=0;
    
    // traduco il codice
	cs_err err = cs_open(CS_ARCH_X86, CS_MODE, &handle);
	if (err) {
		printf("Failed on cs_open() with error returned: %u\n", err);
		return error;
	}
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    
	count = cs_disasm(handle, CODE, size, 0x00, 0, &insn);
    
	if (count > 0) {

		size_t j;
        char * token;
        char * resto;
        int num,no_up=false;
        

		for (j = 0; j < count; j++) {
            
            if(!hdr_is_JUMP(insn[j].id)) continue;

            token = strtok( insn[j].op_str, OPERAND_DELIMITATOR);
            num = (int) strtol(token, &resto, 16);
            if( (num == 0) || ( *resto != '\x0' ) ){
                //write_log(  "Wrong format: JMP r/m\n" );
                continue;
            }
            
            if( binarySearch( lab, 0, cont_label, num) >= 0 ) continue;
            cont_label = insertSorted(lab, cont_label, num);  

            if((cont_label%50)==0){
                lab = realloc( lab, (cont_label+50)*sizeof(int) );
                if ( lab == NULL ){
                    write_log("realloc lab failed\n");
                    sleep(2);
                    exit(1);
                }
            }
        }
		cs_free(insn, count);
    
    } else write_log("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
    return 0;
}

void delete_reg( int i ){
    int j;
    for( j=0; j<4; j++){
        if( (i-(j*16)) >= 0 )
            registri.reg_flag &= ~((unsigned long)1 << (i-(j*16)));
        if( (i+(j*16)) <= 63 )
            registri.reg_flag &= ~((unsigned long)1 << (i+(j*16)));
    }
}
int is_label( uint64_t address){
    int i;
    for( i=0 ; i<cont_label; i++){
        if( address == lab[i]){
            return true;
        }
    }
    return false;
}
int invalider_istruction( cs_insn insn ){
    int i;
    if ( hdr_is_RET(insn.id) || hdr_is_CALL(insn.id) || hdr_is_JUMP(insn.id) )
    {
        for(i=0;i<16;i++) delete_reg(i);
        return true;
    }
    return false;
}
int is_skipdata( unsigned int id){
    if( id == X86_INS_INVALID) return true;
    return false;
}

int hidder_disasm( struct hdr_section_content* hdr_code, struct hdr_data_message* hdr_data ){
    
    // variabili multi uso per return cicli e temporanei
    int i,j,ret,c;
    unsigned char temp;
    unsigned long reg_flag_temp;
    // inizializzo capstone
	csh handle;
	cs_insn *insn;
	size_t count;

    // inizializzo variabili per keystone
    unsigned char ks_output[ADDSUB_INSTR_MAX_LEN];
    int ks_size;
    
    // traduco il codice
	if (cs_open(CS_ARCH_X86, CS_MODE, &handle) != CS_ERR_OK)
		return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

	count = cs_disasm(handle, hdr_code->CODE, hdr_code->section_size, 0, 0, &insn);
    
	if (count > 0) {
		size_t j;
        // salvo dimensione codice 
        cont_istr.size=hdr_code->section_size;

        char* operand;
        int rn,fr;
        registri.reg_flag=0;
        
		for (j = 0; j < count; j++) {
            
            // controllo se ho finito di decodificare.
            if( hdr_data->byte_encoded_size == (hdr_data->cyphertext_len+INT_BYTES_LEN) ){
                write_log("Nascosti tutti e %d bytes\n\n", hdr_data->cyphertext_len );
                break;
            }
              
            /*
            *   controllo che non sia una label, e quindi annulla le operazioni consecutive,
            *   se si pulisco tutti i reg di operazioni consec
            */
            if( ( ret = binarySearch( lab, 0, cont_label, insn[j].address)) >= 0 ){
                for(i=0;i<16;i++) delete_reg(i);
            }
            if( is_skipdata(insn[j].id) ) continue;

            /*
            *   controllo istruzioni toacxs 
            */
            
            switch( ret = match_equivalent_bytes_sets( insn[j], hdr_data, ks_output )){
                case -1:
                    break;
                default:
                    if( insn[j].id == X86_INS_TEST) cont_istr.test1++;
                    if( insn[j].id == X86_INS_OR)   cont_istr.or1++;
                    if( insn[j].id == X86_INS_AND)  cont_istr.and1++;
                    if( insn[j].id == X86_INS_ADD)  cont_istr.add1++;
                    if( insn[j].id == X86_INS_SUB)  cont_istr.sub1++;
                    if( insn[j].id == X86_INS_XOR)  cont_istr.xor1++;
                    if( insn[j].id == X86_INS_CMP)  cont_istr.cmp1++;
                    for (i = 0; i < ret; i++) {
                        hdr_code->CODE[ ( insn[j].address+i) ]= ks_output[i];
                    }
                    break;
            }

            // TODO PER FUTURI LAVORI
            /*switch( ret = match_insn( insn[j], ks_output )){
                case -1:
                    break;
                default:
                    for (i = 0; i < ret; i++) {
                        write_log("%02x %02x |", hdr_code->CODE[(insn[j].address+i)], ks_output[i]);
                        hdr_code->CODE[ ( insn[j].address+i) ]= ks_output[i];
                        
                    }    write_log("\n");
            }*/

            /*
            *   controllo istruzioni toa
            */
            switch( ret = toa_subs( insn, j, count, hdr_data, ks_output )){
                case -1:
                    break;
                default:
                    for (i = 0; i < ret; i++) {
                        hdr_code->CODE[ ( insn[j].address+i) ]= ks_output[i];
                    }
                    break;
            }

            /*
            *   controllo istruzioni xor sub
            */
            switch( (ret = xor_sub_subs( insn[j], hdr_data, ks_output )) ){
                case -1:
                    break;
                default:
                    for (i = 0; i < ret; i++) {
                        hdr_code->CODE[ ( insn[j].address+i) ]= ks_output[i];
                    }
                    break;
            }
            
            /*
            *   controllo istruzioni cmp_rr
            */
            switch( (ret = cmp_subs( insn, j, count, hdr_data, ks_output )) ){
                case BIT_ALREADY_ENCODED:
                    break;
                case error:
                    break;
                default:
                    for (i = 0; i < ret; i++) {
                        hdr_code->CODE[ ( insn[j].address+i) ]= ks_output[i];
                    }
                    break;
            }

            /*
            *   controllo istruzioni add,adc,cmp,mov,sbb
            */
            switch( (ret = aacms_s( insn[j], hdr_data, ks_output )) ){
                
                case error:
                    break;
                default:
                    for (i = 0; i < ret; i++) {
                        hdr_code->CODE[ ( insn[j].address+i) ]= ks_output[i];
                    }
            }

            // stampo solo le istruzioni ADD SUB momentaneamente, TODO un match per ogni 
            // set di istruzioni sostituibili 
            /*write_log("%d 0x%"PRIx64": %s %s\t", insn[j].id, insn[j].address, insn[j].mnemonic,
                insn[j].op_str);
            for( i=0; i<insn[j].size; i++){
                write_log( "%x ", insn[j].bytes[i]);
            }
            write_log( "\n" );*/
                      
            switch( (ret = addsub_imm_s( insn, j, count, hdr_data, ks_output )) ){
                case BIT_ALREADY_ENCODED:
                
                    break;
                case error:
                    if( invalider_istruction(insn[j]) ) break;
                    
                    // declare temp op_str
                    char op_str[160];
                    strcpy( op_str, insn[j].op_str) ;
                    
                    // prendo il primo operando
                    operand = strtok( op_str, OPERAND_DELIMITATOR);
                    if(operand==NULL)goto nope;
                    i = flag_reg(operand);
                    if(i>=0){
                        delete_reg(i);
                        
                    }
                    // cerco gli altri
                    while( operand != NULL ) {
                        operand = strtok(NULL, OPERAND_DELIMITATOR);
                        if(operand==NULL)goto nope;
                        //creo temporaneamente il flag del registro, se l'istruzione sarà valida lo salvo globalmente
                        i = flag_reg(&operand[1]);
                        if(i>=0){
                            delete_reg(i);
                            
                        }
                        
                    }
        nope:
                    for( rn=0; rn<insn[j].detail->regs_write_count; rn++){
                        
                        fr = flag_reg(cs_reg_name( handle, insn[j].detail->regs_write[rn] ));
                        if(fr>=0){
                            delete_reg(fr);
                        }
                    }
                    for( rn=0; rn<insn[j].detail->regs_read_count; rn++){
                        
                        fr = flag_reg(cs_reg_name( handle, insn[j].detail->regs_read[rn] ));
                        if(fr>=0){
                            delete_reg(fr);
                        }
                    }
                    break;
                
                default:
                
                    for (i = 0; i < ret; i++) {
                        hdr_code->CODE[ ( insn[j].address+i) ]= ks_output[i];
                    }
                    
                    break;
            }  
            
		}
		cs_free(insn, count);
	    cs_close(&handle);
    } else write_log("ERROR: Failed to disassemble given code!\n");

}



int decoder_disasm( struct hdr_section_content* hdr_code, struct hdr_data_message* hdr_data ){
    
    // variabili multi uso per return cicli e temporanei
    int i,j,ret;
    unsigned char temp;

    // inizializzo capstone
	csh handle;
	cs_insn *insn;
	size_t count;
    

    // traduco il codice
	if (cs_open(CS_ARCH_X86, CS_MODE, &handle) != CS_ERR_OK)
		return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    
	count = cs_disasm(handle, hdr_code->CODE, hdr_code->section_size, 0, 0, &insn);
    
	
    if (count > 0) {
		size_t j;

		for (j = 0; j < count; j++) {
            
            // controllo se ho finito di decodificare.
            if( hdr_data->byte_encoded_size == (hdr_data->cyphertext_len+INT_BYTES_LEN) ){
                write_log("Rilevati %d bytes\n", hdr_data->cyphertext_len );
                break;
            }
            

            /*
            *   controllo istruzioni toaxrs 
            */
            switch( ret = match_is_sets( insn[j] ) ){
                case -1:
                    break;
                default:
                    put_bits( hdr_data, ret, 2);
                    continue;
            }
            /*
            *   controllo istruzioni toa
            */
            switch( ret = toa_is_subs( insn[j] )){
                case -1:
                    break;
                default:
                    put_bits( hdr_data, ret, 2);
                    continue;
            }

            /*
            *   controllo istruzioni xor_sub
            */
            switch( ret = xor_sub_is_subs( insn[j] )){
                case -1:
                    break;
                default:
                    put_bits( hdr_data, ret, 2);
                    continue;
            }

            /*
            *   controllo istruzioni add_sub
            */
            switch( ret = addsub_imm_is_s( insn, j, count )){
                case -1:
                    break;
                default:
                    put_bits( hdr_data, ret, 1);
                    continue;
            }
            /*
            *   controllo istruzioni cmp_rr
            */
            switch( ret = cmp_is_subs( insn, j, count ) ){
                case -1:
                    break;
                default:
                    put_bits( hdr_data, ret, 1);
                    continue;
            }

            /*
            *   controllo istruzioni aacms
            */
            switch( ret = aacms_is_s( insn[j]) ){
                case -1:
                    break;
                default:
                    put_bits( hdr_data, ret, 1);
                    continue;
            }
        }
        if( hdr_data->byte_encoded_size < (hdr_data->cyphertext_len+INT_BYTES_LEN) ){
            write_log("NON Rilevati tutti e %d bytes\n", hdr_data->cyphertext_len );
        }

        // test decrypt per vedere se funziona
        hdr_data->plaintext = malloc(hdr_data->cyphertext_len);
        if ( hdr_data->plaintext == NULL ){
            write_log("malloc hdr_data->plaintext failed\n");
            sleep(2);
            exit(1);
        }
        decrypt( hdr_data->cyphertext, hdr_data->cyphertext_len, hdr_data->digest, hdr_data->ivec, hdr_data->plaintext);
        hdr_data->plaintext[hdr_data->plaintext_len]='\0';

        cs_free(insn, count);
        
        if(0==e_opt_dec)
        {
            int dim=0;
            do{
                dim += fwrite(hdr_data->plaintext, 1, hdr_data->plaintext_len, hdr_data->f_output);
            }while( dim != hdr_data->plaintext_len );
            write_log("Messaggio decifrato salvato nel file\n");
        }
        else
        {
            // La capacita` di eseguire codice e` un privilegio che puo` essere concesso sulle pagine della memoria
            void *buf = mmap (0 , hdr_data->plaintext_len , PROT_READ|PROT_WRITE|PROT_EXEC , MAP_PRIVATE|MAP_ANON , -1 , 0);
            
            memcpy (buf , hdr_data->plaintext , hdr_data->plaintext_len);
            /*
            Bisogna dire al GCC che opera su x86 che la memcpy non e` una "dead store".
            (GCC pensa che quella memcpy sia dead store perche' afferma che dereferenziare un puntatore a funzione non sia
            equivalente a leggere i byte da quell'indirizzo, dunque avrei problemi quando invoco buf()).
            In verita` la funzione che seguen non svuota alcuna instruction cache: marca la zona di memoria come "usata" in
            modo da permettere davvero la copiatura.
            */
            __builtin___clear_cache(buf , buf+hdr_data->plaintext_len-1); // -1 perche' inizio a contare da 0
            ret = ((int(*)(void))buf)();
            /*
            Si potrebbe analizzare il valore di ret ed eseguire azioni di conseguenza. Tuttavia, siccome il codice inoculato
            svolge operazioni generiche e non note a priori, potrebbe essere restrittivo interrompere sempre e comunque
            il programma decoder se il codice inoculato restituisce -1.
            */
            munmap(buf,hdr_data->plaintext_len);    // Elimino la mappatura della memoria
        }
        
    } else write_log("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
    return 0;    

}
