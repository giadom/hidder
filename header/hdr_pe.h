#ifndef HDR_PE
#define HDR_PE

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>

/**
 *  Questo header contiene le strutture e costanti per leggere file PE 32, PE 32+ 
 *  ( ovvero la versione 64 bit ).
 *  Non contiene ogni flag/costante per i file PE, soltanto ciò che effettivamente 
 *  è utile per il nostro hidder/decoder.
 *  Ogni informazione utilizzata è ricavata dalla documentazione ufficiale windows
 *  reperibile al link https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
 * 
 *  Seguiremo un ordine ovvero:
 * 
    *  MS-DOS Stub (Image Only)
    *       Signature (Image Only)
    *  COFF File Header (Object and Image)
    *       Machine Types
    *       Characteristics
    *  Optional Header (Image Only)
    *       Optional Header Standard Fields (Image Only)
    *       Optional Header Windows-Specific Fields (Image Only)
    *       Optional Header Data Directories (Image Only)
    *  SECTION HEADER
    *  SECTION DATA
*/

/*
*   MS-DOS Stub (image only), è un intestazione di default presente nei file immagine (eseguibili)
*   ha dimensione fissa 0x3c, alla locazione 0x3c è presente un offset che punta ad una signature.
*   La signature è "PE\0\0" ed indica che si tratta di un file PE e da inizio al COFF header.
*/
#define MS_DOS_STUB_SIZE 0x3c

#define SIGNATURE_SIZE 4

#define SIGN_0		0		/* File identification byte 0 index */
#define PESIGN_0	0x50		/* Magic number byte 0 */
#define SIGN_1		1		/* File identification byte 1 index */
#define PESIGN_1	0x45		/* Magic number byte 1 */
#define SIGN_2		2		/* File identification byte 2 index */
#define PESIGN_2	0x00		/* Magic number byte 2 */
#define SIGN_3		3		/* File identification byte 3 index */
#define PESIGN_3	0x00		/* Magic number byte 3 */

#define MAGIC_SIZE 2

#define MAG_0		0		/* File identification byte 0 index */
#define MAG_1		1		/* File identification byte 0 index */
#define PE32MAG_0	0x0b		/* Magic number byte 0 */
#define PE32MAG_1	0x01		/* Magic number byte 1 */
#define PE64MAG_0	0x0b		/* Magic number byte 0 */
#define PE64MAG_1	0x02		/* Magic number byte 1 */

typedef struct ms_dos_stub
{
    char stub[MS_DOS_STUB_SIZE];
    uint32_t offset_signature;
}ms_dos_stub;

/*
*   COFF Header, è un header standard per tutti i tipi di file, sia oggetto che immagine.
*   Ha dimensione e formato fisso ed è il seguente.
*   Ogni variabile è commentata, se seguita dalla parola UTILE allora la medesima è utilizzata
*   nel nostro progetto.
*/
typedef struct coff_file_header
{
    uint8_t Signature[SIGNATURE_SIZE];
    uint16_t Machine;               // ID che indica l'architettura target.
    uint16_t NumberOfSections;      /* indica il numero di sezioni, UTILE poiche
    ci permette di calcolare la dimensione della Section Table */ 
    uint32_t TimeDateStamp;         // indica la data di creazione del file
    uint32_t PointerToSymbolTable;  // offset che indica la COFF symbol table
    uint32_t NumberOfSymbols;       // numero di entry nella symbol table
    uint16_t SizeOfOptionalHeader;  /* dimensione degli optional header, UTILE poiche
    la section table segue sempre gli optional header, pertanto possiamo calcolarci l'offset
    della section table */
    uint16_t Characteristics;       // Flag del file.
}coff_file_header;

/*
*   Elenchiamo alcuni valori fissi di Machine, a noi interessa soltanto i386 e amd64
*/
#define IMAGE_FILE_MACHINE_UNKNOWN = 0x0;
#define IMAGE_FILE_MACHINE_ALPHA = 0x1d3;     // Alpha_AXP
#define IMAGE_FILE_MACHINE_ALPHA64 = 0x284;   // ALPHA64
#define IMAGE_FILE_MACHINE_AM33 = 0x1d3;      // Matsushita AM33
#define IMAGE_FILE_MACHINE_AMD64 = 0x8664;    // x64
#define IMAGE_FILE_MACHINE_ARM = 0x1c0;       // ARM little endian
#define IMAGE_FILE_MACHINE_ARM64 = 0xaa64;    // ARM64 little endian
#define IMAGE_FILE_MACHINE_ARMNT = 0x1c4;     // ARM Thumb-2 little endian
#define IMAGE_FILE_MACHINE_AXP64 = 0x284;     // ALPHA64
#define IMAGE_FILE_MACHINE_CEE = 0xc0ee;
#define IMAGE_FILE_MACHINE_CEF = 0xcef;
#define IMAGE_FILE_MACHINE_EBC = 0xebc;       // EFI byte code
#define IMAGE_FILE_MACHINE_I386 = 0x14c;      // Intel 386 or later processors and compatible processors
#define IMAGE_FILE_MACHINE_IA64 = 0x200;      // Intel Itanium processor family
#define IMAGE_FILE_MACHINE_M32R = 0x9041;     // Mitsubishi M32R little endian
#define IMAGE_FILE_MACHINE_MIPS16 = 0x266;    // MIPS16
#define IMAGE_FILE_MACHINE_MIPSFPU = 0x366;   // MIPS with FPU
#define IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466; // MIPS16 with FPU
#define IMAGE_FILE_MACHINE_POWERPC = 0x1f0;   // Power PC little endian
#define IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1; // Power PC with floating point support
#define IMAGE_FILE_MACHINE_R3000 = 0x166;     // MIPS little endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000 = 0x166;     // MIPS little endian
#define IMAGE_FILE_MACHINE_R10000 = 0x166;    // MIPS little endian
#define IMAGE_FILE_MACHINE_RISCV32 = 0x5032;  // RISC-V 32-bit address space
#define IMAGE_FILE_MACHINE_RISCV64 = 0x5064;  // RISC-V 64-bit address space
#define IMAGE_FILE_MACHINE_RISCV128 = 0x5128; // RISC-V 128-bit address space
#define IMAGE_FILE_MACHINE_SH3 = 0x1a2;       // Hitachi SH3
#define IMAGE_FILE_MACHINE_SH3DSP = 0x1a3;    // Hitachi SH3 DSP
#define IMAGE_FILE_MACHINE_SH4 = 0x1a6;       // Hitachi SH4
#define IMAGE_FILE_MACHINE_SH5 = 0x1a8;       // Hitachi SH5
#define IMAGE_FILE_MACHINE_THUMB = 0x1c2;     // Thumb
#define IMAGE_FILE_MACHINE_TRICORE = 0x520;   // Infineon
#define IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169; // MIPS little-endian WCE v2
/*
*   Elenchiamo alcuni flag di Characteristic
*/
#define IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
#define IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
#define IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004;
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008;
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010;
#define IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020;
#define IMAGE_FILE_BYTES_REVERSED_LO = 0x0080;
#define IMAGE_FILE_32BIT_MACHINE = 0x0100;
#define IMAGE_FILE_DEBUG_STRIPPED = 0x0200;
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400;
#define IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800;
#define IMAGE_FILE_SYSTEM = 0x1000;
#define IMAGE_FILE_DLL = 0x2000;
#define IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000;
#define IMAGE_FILE_BYTES_REVERSED_HI = 0x8000;

/**
 *  Optiona Header, è un header utilizzato soltanto nei file immagine.
 *  La sua dimensione non è fissa, ma indicata nel file header.
 * 
 *  Questo header può essere visto / diviso in 3 header differenti:
 *  1. Campi Standard
 *  2. Windows-specific fields
 *  3. Data directories
*/

/*
*   1. Standard field, l'unica differenza tra PE32 e PE32+ sta nel campo BaseOfData
*/
typedef struct optional_header_32_standard_field {
    uint8_t Magic[MAGIC_SIZE];                    /* questo valore indica la tipologia, UTILE
    per determinare se 32 bit o 64 bit */
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;               /* Nei PE a differenza degli ELF, il codice è 
    situato interamente nella sezione .text, questo valore ne indica la dimensione  */
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;   /* indirizzo di partenza del programma, relativo 
    all'image base address, quando il file è caricato in memoria */
    uint32_t BaseOfCode;    /* indirizzo relativo all'inizio della sezione codice una volta
    caricata in memoria, utilizza image base address */
    uint32_t BaseOfData;    // idem per la sezione data
}oh32_standard_field;

typedef struct optional_header_64_standard_field {
    uint8_t Magic[MAGIC_SIZE];
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
}oh64_standard_field;

/**
 *  2. Windows specific field,
 *  Contiene informazini utili al linker e al loader in windows.
*/
typedef struct optional_header_32_windows_specific {
    uint32_t ImageBase; // image base address quando è caricato il file in memoria
    uint32_t SectionAlignment;  /* allineamento delle sezioni, in bytes (di solito la grandezza
    dell'allineamento di pagina dell'architettura ) */
    uint32_t FileAlignment;     // allineamento per i raw data del file.
    // i prossimi 7 valori indicano numeri di versione
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;

    uint32_t SizeOfImage; // dimensione in byte dell'immagine (inclusi gli header) in memoria
    uint32_t SizeOfHeaders;  // dimensione in byte degli header in memoria
    uint32_t CheckSum;  // checksum dell'image file
    // altre variabili non utili per il progetto
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;

    uint32_t NumberOfRvaAndSizes; /* numero di entry in data directory, UTILE */
}oh32_windows_specific;

/*
*   Struct per i PE32+ (64bit), è identico nel funzionamento e ordine delle variabili.
*   cambia solo il formato, ovvero alcuni campi sono da 64bit invece di 32.
*/
typedef struct optional_header_64_windows_specific {
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
}oh64_windows_specific;

/**
*   3. data directory, sono entry di 8 bytes che indicano un indirizzo VA e la dimensione di una
*   tabella o una stringa che windows usa. Data directory è caricata in memoria per usarla runtime.
*   
*   
*   gli indirizzi VA sono indirizzi identici agli RVA a cui non è stato sottratto il base address
*   dell'immagine. Ogni processo ha il proprio spazio per gli indirizzi VA, i quali sono separati
*   al livello fisico. Questo rende non prevedibile un VA a differenza degli RVA.
*   RVA è l'indirizzo di un elemento dopo che è stato caricato in memoria, sottratto dell'imageBase 
*   address. E' quasi sempre diverso dall'indirizzo fisico dell'elemento in memoria su file su disco.
*
*   
*/
typedef struct data_directory {
    uint32_t VirtualAddress;
    uint32_t Size;
}data_directory;
/*
*   Non avendo un id o un nome, per determinare cosa è puntato da una entry del data directory,
*   si utilizza l'indice dell'entry. Seguono il seguente ordine.
*/
#define DATA_DIR_NUMBER 16
enum data_directory_index {
    DIR_EXPORT = 0,
    DIR_IMPORT = 1,
    DIR_RESOURCE = 2,
    DIR_EXCEPTION = 3,
    DIR_SECURITY = 4,
    DIR_BASERELOC = 5,
    DIR_DEBUG = 6,
    DIR_ARCHITECTURE = 7,
    DIR_GLOBALPTR = 8,
    DIR_TLS = 9,
    DIR_LOAD_CONFIG = 10,
    DIR_BOUND_IMPORT = 11,
    DIR_IAT = 12,
    DIR_DELAY_IMPORT = 13,
    DIR_COM_DESCRIPTOR = 14,
    DIR_RESERVED = 15,
};

/**
 *  Gli header di sezione seguono subito dopo gli optional header,
 *  contengono le informazioni riguardanti ogni sezione.
*/
#define SHORT_NAME_LEN 8 // nelle entry del section header, i nomi corti sono di 8 bytes

typedef struct image_section_header {
    uint8_t Name[SHORT_NAME_LEN];   // nome identificativo
    uint32_t VirtualSize;           // dimensione quando caricato in mem
    uint32_t VirtualAddress;        // indirizzo del primo byte in memoria quando caricata
    uint32_t SizeOfRawData;         // dimensione della sezione su disco, UTILE
    uint32_t PointerToRawData;      // indirizzo della sezione su disco, UTILE
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
}image_section_header;
#endif