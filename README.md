# `hidder `   
Hidder è un tool di steganografia su file eseguibili, sia ELF che PE, sia 32 che 64 bit sull'architettura x86.  
# `istallazione su UBUNTU 16.04+  `   
Le librerie esterne necessarie per il funzionamento sono:
```c
// crypto library
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
// disassembler library
#include <capstone/capstone.h>
// assembler library
#include <keystone/keystone.h>
// formato elf
#include <elf.h>
```
openssl/elf sono al 99% gia presenti, basta aver fatto almeno una volta
>sudo apt-get update && sudo apt-get upgrade    

installare cmake
>sudo apt-get install cmake
### `capstone  `  
capstone è reperibile a questo link github https://github.com/aquynh/capstone, si deve
scaricare il repository oppure scaricare lo zip e decomprimerlo, nel primo caso
```sh
git clone https://github.com/aquynh/capstone.git 
sudo ./make.sh install 
```
### `keystone   `
come per capstone 
```sh
git clone https://github.com/keystone-engine/keystone.git 
mkdir build
cd build
../make-share.sh
sudo make install
sudo ldconfig
```
### `hidder  `
a questo punto scarica questo repository e usa semplicemente 
>make -i

---
---
# `USO`
> ./hidder "path_file_eseguibile" "path_file_output" "path_file_message"        

Il primo parametro è il file eseguibile sul quale nascondere il messaggio, il secondo è il path di dove creare il file clone contenente il messaggio nascosto, infine un file contenente il messaggio da nascondere.
> ./decoder "path_file_da_decodificare" "path_output_file_message"

inserire semplicemente il path del file eseguibile contenente il messaggio nascosto

In entrambe le versioni viene chiesta una Password per criptare il messaggio.
Verrànno anche stampati una serie di valori di debug che permettono di capire in larga scala il funzionamento del programma.

# `Credits`

## `Capstone`
https://github.com/aquynh/capstone , CAPSTONE, ultimo accesso 19/08/2020

## `Keystone`
https://github.com/keystone-engine/keystone , KEYSTONE, ultimo accesso 19/08/2020

## `Hydan`
El-Khalil, R.: Hydan: Hiding Information in Program Binaries (2003). 
http://crazyboy.com/hydan/

### `ELF parser`
https://github.com/TheCodeArtist/elf-parser

