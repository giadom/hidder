# `hidder`   
Hidder è un tool di steganografia su file eseguibili, sia ELF che PE, sia 32 che 64 bit sull'architettura x86.  
# `Installazione su GNU/Linux`   
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
openssl/elf sono spesso già presenti sul sistema operativo. openssl la puoi installare cercando:
>libssl-dev

installare cmake
>sudo apt-get install cmake
### `capstone`
capstone è reperibile a questo link github https://github.com/aquynh/capstone, si deve
scaricare il repository oppure scaricare lo zip e decomprimerlo, nel primo caso
```sh
git clone https://github.com/aquynh/capstone.git
cd capstone
sudo ./make.sh
sudo ./make.sh install 
```
### `keystone`
come per capstone 
```sh
git clone https://github.com/keystone-engine/keystone.git 
cd keystone
mkdir build
cd build
../make-share.sh
sudo make install
sudo ldconfig
```
### `hidder`
A questo punto scarica questo repository come fatto con kesystone e capstone e usa semplicemente:
>make -i

---
---
# `Uso`
Per nascondere il messaggio in "path_file_message" all'interno del file eseguibile "path_file_eseguibile" producendo il file  "path_file_output" digita:
> ./hidder "path_file_eseguibile" "path_file_output" "path_file_message"

Per estrapolare il messaggio contenuto in "path_file_da_decodificare" e metterlo in "path_output_file_message", digita:
> ./decoder "path_file_da_decodificare" "path_output_file_message"

Se il messaggio che è stato inserito al primo passo è in realtà una serie di istruzioni dirette ad essere eseguite su un'architettura x86 direttamente sul processo generato dal programma di decodifica, allora digita:
> ./decoder -e "path_file_da_decodificare"
oppure
> ./decoder "path_file_da_decodificare" -e

In tutte le versioni viene chiesta una password per criptare il messaggio.
Verranno anche stampati una serie di valori di debug che permettono di capire in larga scala il funzionamento del programma.

##### `Credits`

###### `Capstone`
https://github.com/aquynh/capstone , CAPSTONE, ultimo accesso 19/08/2020

###### `Keystone`
https://github.com/keystone-engine/keystone , KEYSTONE, ultimo accesso 19/08/2020

###### `Hydan`
El-Khalil, R.: Hydan: Hiding Information in Program Binaries (2003). 
http://crazyboy.com/hydan/

###### `ELF parser`
https://github.com/TheCodeArtist/elf-parser

