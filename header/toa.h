#ifndef _HDR_TOA_H_
#define _HDR_TOA_H_


#define MAX_MNEMONIC_STRING_LEN 30
#define MAX_MACHINE_CODE_SIZE 10

#define NF 0
#define CF 1  /* carry flag     */
#define ZF 2   /* zero flag      */
#define OF 4  /* overflow flag  */
#define DF 8   /* direction flag  */
#define SF 16   /* sign flag      */
#define PF 32 /* parity flag    */
#define AF 64 /* af */

// flag utili 
#define REG_8_BIT   0
#define REG_16_BIT  1
#define REG_32_BIT  2
#define REG_64_BIT  3

#define REG_R_TYPE   ( 1 << 2 ) 
#define REG_NR_TYPE  ( 0 << 2 )

/*
*   costanti per toa subs
*/
#define R_REGS_PREFIX '\x45'
#define R_64_BIT_REGS_PREFIX '\x4d'

#define TOA_TABLE_SIZE 5

struct table{
    unsigned char opcode[MAX_MACHINE_CODE_SIZE];
    uint64_t flags;
    char mnemo[MAX_MNEMONIC_STRING_LEN];
};

struct insn_sets{
    int table_size;               // numero elementi in table
    int byte_size;          // num byte machine_code
    struct table *table;
};




#endif
